/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package credentials

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
	"github.com/wso2/open-cloud-datacenter/crds/dbaas/internal/harvester"
)

// TenantCredentialsSecretName, InternalSecretName, and TLSSecretName are the
// deterministic Secret names Resolver reads and creates. All three are
// recomputable from the live DBInstance (name/UID) — never status-memory.
func TenantCredentialsSecretName(inst *dbaasv1.DBInstance) string {
	return fmt.Sprintf("pg-%s-credentials", inst.Name)
}

func InternalSecretName(inst *dbaasv1.DBInstance) string {
	return fmt.Sprintf("dbi-%s-internal", inst.UID)
}

func TLSSecretName(inst *dbaasv1.DBInstance) string {
	return fmt.Sprintf("dbi-%s-tls", inst.UID)
}

// Resolver resolves the durable credential/TLS Material for a DBInstance. It
// generates each backing Secret exactly once and reuses it on every later
// call — regenerating after a VM has already booted with the old password/CA
// would diverge from the running instance.
type Resolver struct {
	Client client.Client
	// Established reports whether the instance's VM has already been created.
	// Once it has, a missing durable Secret is a loss to report, never
	// something to regenerate: a new password, internal credential or CA would
	// not match what the booted VM and its database already hold. Nil means
	// "never established" (tests, tools that only ever provision).
	Established func(ctx context.Context, inst *dbaasv1.DBInstance) (bool, error)
	// Scheme is used to stamp a controller owner reference on the tenant
	// credentials Secret (same-namespace). May be nil in tests that don't
	// assert on owner refs.
	Scheme *runtime.Scheme
	// OperatorNamespace is where the two controller-private Secrets (internal
	// DB credentials, TLS) live — outside the tenant namespace.
	OperatorNamespace string
	// DefaultMasterUser is used when spec.masterUsername is omitted.
	DefaultMasterUser string
}

// ErrCredentialsLost: a durable credential Secret is missing for an instance
// whose VM already exists. DBaaS refuses to regenerate it.
var ErrCredentialsLost = errors.New("durable credential material is missing for an already-provisioned instance")

// CredentialsLostError names the missing Secret. It never contains any secret
// value.
type CredentialsLostError struct {
	Namespace string
	Name      string
}

func (e *CredentialsLostError) Error() string {
	return fmt.Sprintf("Secret %s/%s is missing, but this database has already been provisioned; "+
		"DBaaS will not generate a replacement because it would not match the running database. "+
		"Restore the Secret from a backup", e.Namespace, e.Name)
}

func (e *CredentialsLostError) Is(target error) bool { return target == ErrCredentialsLost }

// refuseIfEstablished is called when a durable Secret is not found, before any
// replacement is generated. It returns CredentialsLostError when the VM
// already exists, and nil when this is genuine first-time provisioning (or a
// partial create that never reached a booted VM).
func (r *Resolver) refuseIfEstablished(ctx context.Context, inst *dbaasv1.DBInstance, key types.NamespacedName) error {
	if r.Established == nil {
		return nil
	}
	established, err := r.Established(ctx, inst)
	if err != nil {
		return fmt.Errorf("check whether %s/%s is already provisioned: %w", inst.Namespace, inst.Name, err)
	}
	if established {
		return &CredentialsLostError{Namespace: key.Namespace, Name: key.Name}
	}
	return nil
}

// ResolveResult reports both the resolved material and whether this call
// changed cluster state. Callers use Changed to enforce a reconcile boundary
// and re-observe the persisted Secrets before advancing.
type ResolveResult struct {
	Material *Material
	Changed  bool
	// Source says where the accepted master password came from. It is read
	// from the persisted credentials Secret, so it stays correct on every
	// later pass without re-reading the user's source Secret.
	Source SourceInfo
}

// SourceInfo describes where the accepted master password came from. It never
// contains the password or anything derived from it.
type SourceInfo struct {
	// Source is dbaasv1.CredentialsSourceGenerated or
	// dbaasv1.CredentialsSourceUserProvidedSecret.
	Source string
	// SecretName, SecretUID and ResourceVersion identify the user's Secret at
	// the moment its password was accepted. Empty when Source is Generated.
	SecretName      string
	SecretUID       string
	ResourceVersion string
}

// tenantCredentials is what the tenant credentials Secret holds, plus where its
// password came from.
type tenantCredentials struct {
	adminUser     string
	adminPassword string
	source        SourceInfo
}

// Resolve returns the Material for inst, generating and persisting whatever
// is missing. Existing Secrets are validated but never regenerated or repaired:
// rotating durable material behind an already-booted VM would break it.
func (r *Resolver) Resolve(ctx context.Context, inst *dbaasv1.DBInstance) (ResolveResult, error) {
	// The tenant credentials come first: a missing or unusable user-provided
	// password source must fail before anything else is created.
	tenant, tenantChanged, err := r.getOrCreateTenant(ctx, inst)
	if err != nil {
		return ResolveResult{}, err
	}
	replPw, exporterPw, internalChanged, err := r.getOrCreateInternal(ctx, inst)
	if err != nil {
		return ResolveResult{}, err
	}
	vmName := harvester.VMName(inst.Name)
	tls, tlsChanged, err := r.getOrCreateTLS(ctx, inst, vmName)
	if err != nil {
		return ResolveResult{}, err
	}

	return ResolveResult{
		Material: &Material{
			AdminUser:        tenant.adminUser,
			AdminPassword:    tenant.adminPassword,
			ReplPassword:     replPw,
			ExporterPassword: exporterPw,
			TLS:              tls,
		},
		Changed: tenantChanged || internalChanged || tlsChanged,
		Source:  tenant.source,
	}, nil
}

// getOrCreateTenant resolves the tenant admin-credentials Secret
// (admin_user/admin_password only). On a concurrent-create race it adopts
// the winner's material instead of the caller's, so the returned values
// always match what is actually persisted.
//
// When the Secret does not exist yet, the password comes from the user's
// Secret (spec.credentials) if one is referenced, otherwise it is generated.
// Either way the accepted password is then kept in this Secret and is the only
// place later passes and repaves read it from: the user's Secret is read once,
// at creation, and never again. Editing or deleting it afterwards cannot make a
// retry or a repave use a different password than the database was given.
func (r *Resolver) getOrCreateTenant(ctx context.Context, inst *dbaasv1.DBInstance) (tenantCredentials, bool, error) {
	// Before anything is read: a user's Secret named like our own saved copy
	// would be found below and adopted as if DBaaS had created it.
	if err := checkSourceName(inst); err != nil {
		return tenantCredentials{}, false, err
	}

	key := types.NamespacedName{Namespace: inst.Namespace, Name: TenantCredentialsSecretName(inst)}
	var sec corev1.Secret
	if getErr := r.Client.Get(ctx, key, &sec); getErr == nil {
		creds, err := tenantMaterialFrom(&sec, key)
		return creds, false, err
	} else if !apierrors.IsNotFound(getErr) {
		return tenantCredentials{}, false, getErr
	}

	if err := r.refuseIfEstablished(ctx, inst, key); err != nil {
		return tenantCredentials{}, false, err
	}

	adminUser := inst.Spec.MasterUsername
	if adminUser == "" {
		adminUser = r.DefaultMasterUser
	}
	if adminUser == "" {
		return tenantCredentials{}, false, fmt.Errorf("default master user must not be empty")
	}

	var (
		adminPassword string
		source        = SourceInfo{Source: dbaasv1.CredentialsSourceGenerated}
		annotations   map[string]string
	)
	if inst.Spec.Credentials != nil {
		accepted, err := r.ResolvePasswordSource(ctx, inst)
		if err != nil {
			return tenantCredentials{}, false, err
		}
		adminPassword = accepted.Password
		source = SourceInfo{
			Source:          dbaasv1.CredentialsSourceUserProvidedSecret,
			SecretName:      inst.Spec.Credentials.PasswordSource.SecretRef.Name,
			SecretUID:       string(accepted.SecretUID),
			ResourceVersion: accepted.ResourceVersion,
		}
		annotations = map[string]string{
			dbaasv1.AnnotationPasswordSourceSecret:          source.SecretName,
			dbaasv1.AnnotationPasswordSourceUID:             source.SecretUID,
			dbaasv1.AnnotationPasswordSourceResourceVersion: source.ResourceVersion,
		}
	} else {
		var err error
		adminPassword, err = randomString(32)
		if err != nil {
			return tenantCredentials{}, false, fmt.Errorf("generate admin password: %w", err)
		}
	}

	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        key.Name,
			Namespace:   key.Namespace,
			Labels:      map[string]string{dbaasv1.LabelInstance: inst.Name},
			Annotations: annotations,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{"admin_user": adminUser, "admin_password": adminPassword},
	}
	if r.Scheme != nil {
		if err := controllerutil.SetControllerReference(inst, newSec, r.Scheme); err != nil {
			return tenantCredentials{}, false, err
		}
	}
	if err := r.Client.Create(ctx, newSec); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return tenantCredentials{}, false, err
		}
		// race winner already created the secret
		var won corev1.Secret
		if gerr := r.Client.Get(ctx, key, &won); gerr != nil {
			return tenantCredentials{}, false, gerr
		}
		creds, err := tenantMaterialFrom(&won, key)
		return creds, true, err
	}
	return tenantCredentials{adminUser: adminUser, adminPassword: adminPassword, source: source}, true, nil
}

// getOrCreateInternal resolves the operator-namespace internal-credentials
// Secret (repl_password, exporter_password).
func (r *Resolver) getOrCreateInternal(ctx context.Context, inst *dbaasv1.DBInstance) (replPw, exporterPw string, changed bool, err error) {
	key := types.NamespacedName{Namespace: r.OperatorNamespace, Name: InternalSecretName(inst)}
	var sec corev1.Secret
	if getErr := r.Client.Get(ctx, key, &sec); getErr == nil {
		replPw, exporterPw, err = internalMaterialFrom(&sec, key)
		return replPw, exporterPw, false, err
	} else if !apierrors.IsNotFound(getErr) {
		return "", "", false, getErr //Transient Error
	}

	if err := r.refuseIfEstablished(ctx, inst, key); err != nil {
		return "", "", false, err
	}

	replPw, err = randomString(32)
	if err != nil {
		return "", "", false, fmt.Errorf("generate replication password: %w", err)
	}
	exporterPw, err = randomString(24)
	if err != nil {
		return "", "", false, fmt.Errorf("generate exporter password: %w", err)
	}

	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
			Labels: map[string]string{
				dbaasv1.LabelInstance:      inst.Name,
				dbaasv1.LabelDBInstanceUID: string(inst.UID),
			},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{"repl_password": replPw, "exporter_password": exporterPw},
	}
	if err := r.Client.Create(ctx, newSec); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return "", "", false, err
		}
		var won corev1.Secret
		if gerr := r.Client.Get(ctx, key, &won); gerr != nil {
			return "", "", false, gerr
		}
		replPw, exporterPw, err = internalMaterialFrom(&won, key)
		return replPw, exporterPw, true, err
	}
	return replPw, exporterPw, true, nil
}

// getOrCreateTLS resolves the operator-namespace private TLS Secret: CA +
// server cert signed by it, CN/SAN = vmName.
func (r *Resolver) getOrCreateTLS(ctx context.Context, inst *dbaasv1.DBInstance, vmName string) (*TLSBundle, bool, error) {
	key := types.NamespacedName{Namespace: r.OperatorNamespace, Name: TLSSecretName(inst)}
	var sec corev1.Secret
	if getErr := r.Client.Get(ctx, key, &sec); getErr == nil {
		bundle, err := tlsBundleFrom(&sec, key)
		return bundle, false, err
	} else if !apierrors.IsNotFound(getErr) {
		return nil, false, getErr
	}

	if err := r.refuseIfEstablished(ctx, inst, key); err != nil {
		return nil, false, err
	}

	bundle, genErr := generateTLS(vmName)
	if genErr != nil {
		return nil, false, fmt.Errorf("TLS generation: %w", genErr)
	}

	newSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      key.Name,
			Namespace: key.Namespace,
			Labels: map[string]string{
				dbaasv1.LabelInstance:      inst.Name,
				dbaasv1.LabelDBInstanceUID: string(inst.UID),
			},
		},
		Type: corev1.SecretTypeTLS,
		StringData: map[string]string{
			"ca.crt":  bundle.CACertPEM,
			"ca.key":  bundle.CAKeyPEM,
			"tls.crt": bundle.ServerCertPEM,
			"tls.key": bundle.ServerKeyPEM,
		},
	}
	if err := r.Client.Create(ctx, newSec); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return nil, false, err
		}
		var won corev1.Secret
		if gerr := r.Client.Get(ctx, key, &won); gerr != nil {
			return nil, false, gerr
		}
		wonBundle, err := tlsBundleFrom(&won, key)
		return wonBundle, true, err
	}
	return bundle, true, nil
}

// get reads a Secret key from Data (populated by the apiserver), falling back
// to StringData (set on a freshly built object, e.g. under the fake client).
func get(s *corev1.Secret, key string) string {
	if v, ok := s.Data[key]; ok {
		return string(v)
	}
	return s.StringData[key]
}

func tenantMaterialFrom(s *corev1.Secret, key types.NamespacedName) (tenantCredentials, error) {
	user, password := get(s, "admin_user"), get(s, "admin_password")
	if user == "" || password == "" {
		return tenantCredentials{}, fmt.Errorf("credentials secret %s/%s is missing admin_user or admin_password", key.Namespace, key.Name)
	}
	return tenantCredentials{adminUser: user, adminPassword: password, source: sourceInfoFrom(s)}, nil
}

// sourceInfoFrom reads where a persisted credentials Secret's password came
// from. A Secret without the source annotations was generated by the
// controller, which includes every Secret created before user-provided
// passwords existed.
func sourceInfoFrom(s *corev1.Secret) SourceInfo {
	name := s.Annotations[dbaasv1.AnnotationPasswordSourceSecret]
	if name == "" {
		return SourceInfo{Source: dbaasv1.CredentialsSourceGenerated}
	}
	return SourceInfo{
		Source:          dbaasv1.CredentialsSourceUserProvidedSecret,
		SecretName:      name,
		SecretUID:       s.Annotations[dbaasv1.AnnotationPasswordSourceUID],
		ResourceVersion: s.Annotations[dbaasv1.AnnotationPasswordSourceResourceVersion],
	}
}

func internalMaterialFrom(s *corev1.Secret, key types.NamespacedName) (string, string, error) {
	repl, exporter := get(s, "repl_password"), get(s, "exporter_password")
	if repl == "" || exporter == "" {
		return "", "", fmt.Errorf("internal credentials secret %s/%s is missing repl_password or exporter_password", key.Namespace, key.Name)
	}
	return repl, exporter, nil
}

func tlsBundleFrom(s *corev1.Secret, key types.NamespacedName) (*TLSBundle, error) {
	bundle := &TLSBundle{
		CACertPEM:     get(s, "ca.crt"),
		CAKeyPEM:      get(s, "ca.key"),
		ServerCertPEM: get(s, "tls.crt"),
		ServerKeyPEM:  get(s, "tls.key"),
	}
	if bundle.CACertPEM == "" || bundle.CAKeyPEM == "" || bundle.ServerCertPEM == "" || bundle.ServerKeyPEM == "" {
		return nil, fmt.Errorf("TLS secret %s/%s is missing required CA or server certificate material", key.Namespace, key.Name)
	}
	return bundle, nil
}
