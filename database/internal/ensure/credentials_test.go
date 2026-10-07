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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	kubevirtv1 "kubevirt.io/api/core/v1"
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

// seedDurableCredentials stores the three durable Secrets the way first-time
// provisioning does before the VM exists. It bypasses the "established" guard on
// purpose: tests that start from an already-booted instance (appliedSpec set, VM
// present) need its Secrets to exist, and a real booted instance always has them.
func seedDurableCredentials(t *testing.T, ctx context.Context, r *testHarness, inst *dbaasv1.DBInstance) {
	t.Helper()
	resolver := r.credentialsResolver()
	resolver.Established = nil
	if _, err := resolver.Resolve(ctx, inst); err != nil {
		t.Fatalf("seed durable credentials: %v", err)
	}
}

func secretKeys(inst *dbaasv1.DBInstance) []types.NamespacedName {
	return []types.NamespacedName{
		{Namespace: "tenant-a", Name: credentials.TenantCredentialsSecretName(inst)},
		{Namespace: "dbaas-system", Name: credentials.InternalSecretName(inst)},
		{Namespace: "dbaas-system", Name: credentials.TLSSecretName(inst)},
	}
}

func secretExists(r *testHarness, key types.NamespacedName) bool {
	var sec corev1.Secret
	return r.Get(context.Background(), key, &sec) == nil
}

func assertNoSecretsCreated(t *testing.T, r *testHarness, inst *dbaasv1.DBInstance) {
	t.Helper()
	for _, key := range secretKeys(inst) {
		if secretExists(r, key) {
			t.Errorf("Secret %s was created", key)
		}
	}
}

// drainEvents returns the Warning/Normal events recorded so far.
func drainEvents(r *testHarness) []string {
	rec, ok := r.Recorder.(*record.FakeRecorder)
	if !ok {
		return nil
	}
	var out []string
	for {
		select {
		case e := <-rec.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// --- a missing user-provided password source ---

func TestEnsureCredentialsMissingSourceWaitsAndCreatesNothing(t *testing.T) {
	ctx := context.Background()
	inst := byoProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst) // no source Secret yet

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonPasswordSourceNotFound ||
		res.ControllerResult.RequeueAfter != credentialSourceRequeue {
		t.Fatalf("result = %+v, want Pending/PasswordSourceNotFound after %s", res, credentialSourceRequeue)
	}
	cond := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(dbaasv1.ReasonPasswordSourceNotFound) {
		t.Fatalf("CredentialsReady = %+v, want False/PasswordSourceNotFound", cond)
	}
	if !strings.Contains(cond.Message, "orders-pw") {
		t.Errorf("message %q should name the missing Secret", cond.Message)
	}
	assertNoSecretsCreated(t, r, inst)

	// The user creates the Secret: the next pass proceeds.
	created := byoSourceSecret()
	created.ResourceVersion = "" // the API server assigns it on Create
	if err := r.Create(ctx, created); err != nil {
		t.Fatal(err)
	}
	convergeCredentials(t, ctx, r, inst)
	if !inst.Status.IsConditionTrue(dbaasv1.ConditionCredentialsReady) {
		t.Fatal("CredentialsReady should be True once the source exists")
	}
}

func TestEnsureCredentialsInvalidSourceWaitsWithoutLeakingThePassword(t *testing.T) {
	ctx := context.Background()
	inst := byoProvisionInst()
	bad := byoSourceSecret()
	bad.Type = corev1.SecretTypeOpaque // wrong type
	bad.Data["password"] = []byte("TOPSECRETMARKER-password")
	r := newTestHarness(t, &stubHarvester{}, inst, bad)

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonPasswordSourceInvalid ||
		res.ControllerResult.RequeueAfter != credentialSourceRequeue {
		t.Fatalf("result = %+v, want Pending/PasswordSourceInvalid after %s", res, credentialSourceRequeue)
	}
	cond := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Reason != string(dbaasv1.ReasonPasswordSourceInvalid) {
		t.Fatalf("CredentialsReady = %+v", cond)
	}
	if strings.Contains(cond.Message, "TOPSECRETMARKER") || strings.Contains(res.Message, "TOPSECRETMARKER") {
		t.Fatalf("condition leaks the password: %q", cond.Message)
	}
	assertNoSecretsCreated(t, r, inst)

	// The user fixes the type: provisioning continues.
	fixed := byoSourceSecret()
	fixed.ResourceVersion = ""
	fixed.Data["password"] = []byte("TOPSECRETMARKER-password")
	var live corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "orders-pw"}, &live); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, &live); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(ctx, fixed); err != nil {
		t.Fatal(err)
	}
	convergeCredentials(t, ctx, r, inst)
}

// --- a lost durable Secret on an instance whose VM already exists ---

func TestEnsureCredentialsLostWhenAppliedSpecShowsTheVMWasCreated(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Status.AppliedSpec = &dbaasv1.AppliedSpec{NetworkRef: inst.Spec.NetworkRef}
	r := newTestHarness(t, &stubHarvester{}, inst) // no Secrets at all

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonCredentialsLost ||
		res.ControllerResult.RequeueAfter != credentialSourceRequeue {
		t.Fatalf("result = %+v, want Pending/CredentialsLost after %s", res, credentialSourceRequeue)
	}
	cond := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(dbaasv1.ReasonCredentialsLost) {
		t.Fatalf("CredentialsReady = %+v, want False/CredentialsLost", cond)
	}
	assertNoSecretsCreated(t, r, inst)
}

func TestEnsureCredentialsLostWhenTheVMExistsEvenIfStatusWasNotSaved(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst() // appliedSpec nil: the crash-after-create-before-status gap
	r := newTestHarness(t, &stubHarvester{}, inst, testVM("pg-orders", "tenant-a"))

	res := r.ensureCredentials(ctx, inst)

	if res.Reason != dbaasv1.ReasonCredentialsLost {
		t.Fatalf("result = %+v, want CredentialsLost (the live VM proves it was created)", res)
	}
	assertNoSecretsCreated(t, r, inst)
}

// The review's required case: a VM create that failed leaves the cloud-init
// Secret name and VM name in status, but no VM and no database. Losing the
// credentials then must NOT be treated as unrecoverable.
func TestEnsureCredentialsNotLostWhenVMCreationNeverSucceeded(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Status.Resources.CloudInitSecretName = "pg-orders-cloudinit"
	inst.Status.Resources.VMName = "pg-orders"
	// no AppliedSpec, no VirtualMachine in the cluster
	r := newTestHarness(t, &stubHarvester{}, inst)

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomePending || res.Reason != dbaasv1.ReasonCredentialsCreated {
		t.Fatalf("result = %+v, want a normal Pending/CredentialsCreated, not CredentialsLost", res)
	}
	if !inst.Status.IsConditionTrue(dbaasv1.ConditionCredentialsReady) {
		t.Fatal("CredentialsReady should be True")
	}
	for _, key := range secretKeys(inst) {
		if !secretExists(r, key) {
			t.Errorf("Secret %s was not recreated", key)
		}
	}
}

func TestEnsureCredentialsLostEventIsEmittedOnceNotOnEveryPoll(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Status.AppliedSpec = &dbaasv1.AppliedSpec{NetworkRef: inst.Spec.NetworkRef}
	r := newTestHarness(t, &stubHarvester{}, inst)

	for i := 0; i < 4; i++ {
		if res := r.ensureCredentials(ctx, inst); res.Reason != dbaasv1.ReasonCredentialsLost {
			t.Fatalf("poll %d result = %+v", i, res)
		}
	}
	events := drainEvents(r)
	if len(events) != 1 || !strings.Contains(events[0], "Warning") || !strings.Contains(events[0], "CredentialsLost") {
		t.Fatalf("events = %v, want exactly one Warning CredentialsLost", events)
	}
}

func TestEnsureCredentialsRecoversOnceTheSecretIsRestored(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst)
	convergeCredentials(t, ctx, r, inst)

	key := secretKeys(inst)[0]
	var original corev1.Secret
	if err := r.Get(ctx, key, &original); err != nil {
		t.Fatal(err)
	}
	password := string(original.Data["admin_password"])
	if password == "" {
		password = original.StringData["admin_password"]
	}

	// The VM is created, then the credentials Secret is lost.
	inst.Status.AppliedSpec = &dbaasv1.AppliedSpec{NetworkRef: inst.Spec.NetworkRef}
	if err := r.Delete(ctx, &original); err != nil {
		t.Fatal(err)
	}
	if res := r.ensureCredentials(ctx, inst); res.Reason != dbaasv1.ReasonCredentialsLost {
		t.Fatalf("result = %+v, want CredentialsLost", res)
	}
	if secretExists(r, key) {
		t.Fatal("a replacement Secret was generated")
	}

	// An admin restores it from a backup.
	restored := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name},
		StringData: map[string]string{"admin_user": "dbadmin", "admin_password": password},
	}
	if err := r.Create(ctx, restored); err != nil {
		t.Fatal(err)
	}
	if res := r.ensureCredentials(ctx, inst); res.Outcome != OutcomeSatisfied {
		t.Fatalf("after restore result = %+v, want Satisfied", res)
	}
	cond := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Status != metav1.ConditionTrue || cond.Reason != string(dbaasv1.ReasonCredentialsProvisioned) {
		t.Fatalf("CredentialsReady = %+v, want True/CredentialsProvisioned", cond)
	}
}

// The same rule covers the platform-owned Secrets: a regenerated TLS CA or
// exporter password would not match the running VM either.
func TestEnsureCredentialsLostCoversInternalAndTLSSecrets(t *testing.T) {
	for i, what := range []string{"credentials", "internal", "TLS"} {
		t.Run(what, func(t *testing.T) {
			ctx := context.Background()
			inst := newProvisionInst()
			r := newTestHarness(t, &stubHarvester{}, inst)
			convergeCredentials(t, ctx, r, inst)
			inst.Status.AppliedSpec = &dbaasv1.AppliedSpec{NetworkRef: inst.Spec.NetworkRef}

			key := secretKeys(inst)[i]
			var sec corev1.Secret
			if err := r.Get(ctx, key, &sec); err != nil {
				t.Fatal(err)
			}
			if err := r.Delete(ctx, &sec); err != nil {
				t.Fatal(err)
			}

			res := r.ensureCredentials(ctx, inst)
			if res.Reason != dbaasv1.ReasonCredentialsLost {
				t.Fatalf("result = %+v, want CredentialsLost", res)
			}
			if !strings.Contains(res.Message, key.Name) {
				t.Errorf("message %q should name %s", res.Message, key.Name)
			}
			if secretExists(r, key) {
				t.Fatalf("%s was regenerated", key)
			}
		})
	}
}

// A failure to find out whether the VM exists is a plain transient error: it
// must not read as "lost" (which would raise an alarm) or "not established"
// (which would regenerate a password).
func TestEnsureCredentialsEstablishedLookupFailureIsTransient(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	r := newTestHarness(t, &stubHarvester{}, inst)
	boom := errors.New("apiserver unavailable")
	watch, ok := r.Client.(client.WithWatch)
	if !ok {
		t.Fatal("fake client does not implement client.WithWatch")
	}
	r.Client = interceptor.NewClient(watch, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, isVM := obj.(*kubevirtv1.VirtualMachine); isVM {
				return boom
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	res := r.ensureCredentials(ctx, inst)

	if res.Outcome != OutcomeTransient || !errors.Is(res.Err, boom) {
		t.Fatalf("result = %+v, want Transient wrapping the lookup error", res)
	}
	assertNoSecretsCreated(t, r, inst)
}
