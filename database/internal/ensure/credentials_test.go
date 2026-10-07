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

package ensure

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
	"github.com/wso2/open-cloud-datacenter/crds/dbaas/internal/credentials"
	dbresource "github.com/wso2/open-cloud-datacenter/crds/dbaas/internal/resource"
)

func TestEnsureCredentialsResolvesAndRecordsRefsWithoutEndpoint(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst() // no Endpoint yet
	r := newTestHarness(t, &stubHarvester{}, inst)

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomePending || res.ControllerResult.RequeueAfter != credentialRequeue {
		t.Fatalf("first result = %+v, want timed Pending", res)
	}
	refs := inst.Status.Resources
	if refs.AdminCredentialsSecretName != "pg-orders-credentials" {
		t.Fatalf("AdminCredentialsSecretName = %q, want pg-orders-credentials", refs.AdminCredentialsSecretName)
	}
	if refs.InternalSecretRef != "dbaas-system/dbi-orders-uid-internal" {
		t.Fatalf("InternalSecretRef = %q", refs.InternalSecretRef)
	}
	if refs.PrivateTLSSecretRef != "dbaas-system/dbi-orders-uid-tls" {
		t.Fatalf("PrivateTLSSecretRef = %q", refs.PrivateTLSSecretRef)
	}
	if !inst.Status.IsConditionTrue(dbaasv1.ConditionCredentialsReady) {
		t.Fatal("CredentialsReady should be True")
	}
	if got := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady).Reason; got != string(dbaasv1.ReasonCredentialsCreated) {
		t.Fatalf("CredentialsReady reason = %q, want CredentialsCreated", got)
	}

	res = r.ensureCredentials(ctx, inst)
	if res.Outcome != OutcomeSatisfied {
		t.Fatalf("second result = %+v, want Satisfied after observation", res)
	}

	// No endpoint yet: the connection Secret must not be created or referenced.
	if got := inst.Status.Resources.ConnectionSecretName; got != "" {
		t.Fatalf("ConnectionSecretName = %q, want empty (no endpoint yet)", got)
	}
	var conn corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: dbresource.ConnectionSecretName(inst)}, &conn); err == nil {
		t.Fatal("connection secret should not exist before an endpoint is known")
	}

	// All three durable secrets actually exist in the cluster.
	var tenant corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-credentials"}, &tenant); err != nil {
		t.Fatalf("tenant credentials secret missing: %v", err)
	}
	var internal corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "dbaas-system", Name: credentials.InternalSecretName(inst)}, &internal); err != nil {
		t.Fatalf("internal secret missing: %v", err)
	}
	var tls corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "dbaas-system", Name: credentials.TLSSecretName(inst)}, &tls); err != nil {
		t.Fatalf("TLS secret missing: %v", err)
	}
}

func TestEnsureCredentialsPublishesConnectionSecretOnceEndpointKnown(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Status.Endpoint = &dbaasv1.Endpoint{Address: "192.168.40.50", Port: defaultPort}
	r := newTestHarness(t, &stubHarvester{}, inst)

	convergeCredentials(t, ctx, r, inst)
	res := r.ensureConnectionSecret(ctx, inst)

	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonConnectionSecretReconciled {
		t.Fatalf("first connection result = %+v, want Pending/ConnectionSecretReconciled", res)
	}
	if inst.Status.Resources.ConnectionSecretName != "pg-orders-connect" {
		t.Fatalf("ConnectionSecretName = %q, want pg-orders-connect", inst.Status.Resources.ConnectionSecretName)
	}

	var conn corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-connect"}, &conn); err != nil {
		t.Fatalf("connection secret missing: %v", err)
	}
	if string(conn.Data["host"]) != "192.168.40.50" || string(conn.Data["dbname"]) != "orders" {
		t.Fatalf("Data = %+v", conn.Data)
	}
	if len(conn.Data["ca.crt"]) == 0 {
		t.Fatal("connection secret must carry the CA cert once TLS material is resolved")
	}
	if refs := conn.GetOwnerReferences(); len(refs) != 1 || refs[0].Kind != "DBInstance" {
		t.Fatalf("connection secret owner refs = %+v, want controller-owned", refs)
	}
	if res = r.ensureConnectionSecret(ctx, inst); res.Outcome != OutcomeSatisfied {
		t.Fatalf("second connection result = %+v, want Satisfied", res)
	}
}

// A resolve failure (material genuinely can't be established) blocks
// provisioning — ensureVM depends on it — so it must be Transient, not
// swallowed like the connection-secret best-effort path below.
func TestEnsureCredentialsResolveFailureIsTransient(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	// Seed a broken tenant secret (missing admin_password) so Resolve fails.
	broken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "pg-orders-credentials", Namespace: "tenant-a"},
		Data:       map[string][]byte{"admin_user": []byte("dbadmin")},
	}
	r := newTestHarness(t, &stubHarvester{}, inst, broken)

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomeTransient || res.Err == nil {
		t.Fatalf("res = %+v, want Transient with error", res)
	}
	cond := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "CredentialsResolveFailed" {
		t.Fatalf("CredentialsReady = %+v, want False/CredentialsResolveFailed", cond)
	}
}

func TestEnsureConnectionSecretFailureIsTransient(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Status.Endpoint = &dbaasv1.Endpoint{Address: "192.168.40.50", Port: defaultPort}

	boom := errors.New("apiserver unavailable")
	r := newTestHarness(t, &stubHarvester{}, inst)
	convergeCredentials(t, ctx, r, inst)
	watchClient, ok := r.Client.(client.WithWatch)
	if !ok {
		t.Fatal("fixture's fake client does not implement client.WithWatch")
	}
	r.Client = interceptor.NewClient(watchClient, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if sec, ok := obj.(*corev1.Secret); ok && sec.Name == dbresource.ConnectionSecretName(inst) {
				return boom
			}
			return c.Create(ctx, obj, opts...)
		},
	})

	res := r.ensureConnectionSecret(ctx, inst)

	if res.Outcome != OutcomeTransient || !errors.Is(res.Err, boom) {
		t.Fatalf("result = %+v, want Transient with apply error", res)
	}
	if inst.Status.Resources.ConnectionSecretName != "" {
		t.Fatalf("ConnectionSecretName = %q, want unset after a failed apply", inst.Status.Resources.ConnectionSecretName)
	}
}

func TestEnsureConnectionSecretWaitsForEndpoint(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst)
	convergeCredentials(t, ctx, r, inst)

	res := r.ensureConnectionSecret(ctx, inst)
	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonWaitingForEndpoint || res.ControllerResult.RequeueAfter != credentialRequeue {
		t.Fatalf("result = %+v, want timed Pending/WaitingForEndpoint", res)
	}
}

func convergeCredentials(t *testing.T, ctx context.Context, r *testHarness, inst *dbaasv1.DBInstance) {
	t.Helper()
	if res := r.ensureCredentials(ctx, inst); res.Outcome != OutcomePending {
		t.Fatalf("credential create result = %+v, want Pending", res)
	}
	if res := r.ensureCredentials(ctx, inst); res.Outcome != OutcomeSatisfied {
		t.Fatalf("credential observe result = %+v, want Satisfied", res)
	}
}

func byoProvisionInst() *dbaasv1.DBInstance {
	inst := newProvisionInst()
	inst.Spec.Credentials = &dbaasv1.CredentialsSpec{
		PasswordSource: dbaasv1.PasswordSource{SecretRef: dbaasv1.PasswordSecretRef{Name: "orders-pw", Key: "password"}},
	}
	return inst
}

func byoSourceSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "orders-pw", UID: "src-uid", ResourceVersion: "42"},
		Type:       dbaasv1.PasswordSecretType,
		Data:       map[string][]byte{"password": []byte("a-user-chosen-password")},
	}
}

func TestEnsureCredentialsRecordsTheUserProvidedSourceInStatus(t *testing.T) {
	ctx := context.Background()
	inst := byoProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst, byoSourceSecret())

	convergeCredentials(t, ctx, r, inst)

	got := inst.Status.Credentials
	if got == nil {
		t.Fatal("status.credentials not set")
	}
	if got.Source != dbaasv1.CredentialsSourceUserProvidedSecret || got.SourceSecretName != "orders-pw" ||
		got.SourceUID != "src-uid" || got.SourceResourceVersion != "42" {
		t.Fatalf("status.credentials = %+v", got)
	}
	if got.SourceChanged {
		t.Fatal("SourceChanged must start false")
	}

	var tenant corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-credentials"}, &tenant); err != nil {
		t.Fatal(err)
	}
	if tenant.StringData["admin_password"] != "a-user-chosen-password" {
		t.Fatal("credentials Secret does not hold the user-provided password")
	}
}

func TestEnsureCredentialsRecordsGeneratedSourceForDefaultInstances(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst)

	convergeCredentials(t, ctx, r, inst)

	got := inst.Status.Credentials
	if got == nil || got.Source != dbaasv1.CredentialsSourceGenerated || got.SourceSecretName != "" {
		t.Fatalf("status.credentials = %+v, want Generated with no source Secret", got)
	}
}

// SourceChanged is set by the source-change check, not by resolution. Resolving
// again on later passes must not reset it.
func TestEnsureCredentialsDoesNotResetSourceChanged(t *testing.T) {
	ctx := context.Background()
	inst := byoProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst, byoSourceSecret())
	convergeCredentials(t, ctx, r, inst)

	inst.Status.Credentials.SourceChanged = true
	if res := r.ensureCredentials(ctx, inst); res.Outcome != OutcomeSatisfied {
		t.Fatalf("result = %+v, want Satisfied", res)
	}
	if !inst.Status.Credentials.SourceChanged {
		t.Fatal("a later resolution pass reset SourceChanged")
	}
}

func TestEnsureCredentialsMissingSourceBlocksProvisioningAndCreatesNothing(t *testing.T) {
	ctx := context.Background()
	inst := byoProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst) // no source Secret

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomeTransient || !errors.Is(res.Err, credentials.ErrPasswordSourceNotFound) {
		t.Fatalf("result = %+v, want Transient wrapping ErrPasswordSourceNotFound", res)
	}
	if inst.Status.IsConditionTrue(dbaasv1.ConditionCredentialsReady) {
		t.Fatal("CredentialsReady must not be True without a password")
	}
	for _, key := range []types.NamespacedName{
		{Namespace: "tenant-a", Name: "pg-orders-credentials"},
		{Namespace: "dbaas-system", Name: credentials.InternalSecretName(inst)},
		{Namespace: "dbaas-system", Name: credentials.TLSSecretName(inst)},
	} {
		var sec corev1.Secret
		if err := r.Get(ctx, key, &sec); err == nil {
			t.Errorf("Secret %s was created despite the missing source", key)
		}
	}
}
