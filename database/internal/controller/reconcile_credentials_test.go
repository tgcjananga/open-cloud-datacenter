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

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
	"github.com/wso2/open-cloud-datacenter/crds/dbaas/internal/harvester"
)

const userChosenPassword = "a-user-chosen-password"

// walkToAvailable drives the real step chain until the instance is Available,
// creating the VirtualMachine out of band the way KubeVirt would.
func walkToAvailable(t *testing.T, ctx context.Context, r *DBInstanceReconciler, inst *dbaasv1.DBInstance, stub *stubHarvester) *dbaasv1.DBInstance {
	t.Helper()
	key := client.ObjectKeyFromObject(inst)
	for pass := 1; pass <= 12; pass++ {
		if err := r.Get(ctx, key, inst); err != nil {
			t.Fatalf("pass %d refetch: %v", pass, err)
		}
		if _, err := runReconcileInstance(ctx, r, inst); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
		ensureVMObject(t, ctx, r, stub)
		got := &dbaasv1.DBInstance{}
		if err := r.Get(ctx, key, got); err != nil {
			t.Fatalf("pass %d get: %v", pass, err)
		}
		if got.Status.Phase == dbaasv1.StatusAvailable && got.Status.ObservedGeneration == got.Generation {
			return got
		}
	}
	t.Fatal("instance did not reach Available within 12 passes")
	return nil
}

// ensureVMObject plays KubeVirt: once the provider was asked to create the VM,
// the VirtualMachine object appears in the cluster.
func ensureVMObject(t *testing.T, ctx context.Context, r *DBInstanceReconciler, stub *stubHarvester) {
	t.Helper()
	if stub.CreateVMCalls == 0 {
		return
	}
	var vm kubevirtv1.VirtualMachine
	err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders"}, &vm)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, testVM("pg-orders", "tenant-a")); err != nil {
			t.Fatalf("create vm: %v", err)
		}
	} else if err != nil {
		t.Fatalf("get vm: %v", err)
	}
}

// drainRecorder returns every event recorded so far and empties the recorder.
func drainRecorder(r *DBInstanceReconciler) []string {
	rec := r.Recorder.(*record.FakeRecorder)
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

func availableStub() *stubHarvester {
	return &stubHarvester{Readiness: harvester.VMIReadiness{Running: true, IP: "192.168.40.50", Ready: true}}
}

// The plan's "delete the credentials Secret after Available" scenario, through
// the real chain: the database keeps working, nothing is regenerated, and the
// loss is reported.
func TestReconcileLostCredentialsSecretIsReportedNotReplaced(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	stub := availableStub()
	r := newProvisionReconciler(t, stub, inst)
	got := walkToAvailable(t, ctx, r, inst, stub)

	key := types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-credentials"}
	var sec corev1.Secret
	if err := r.Get(ctx, key, &sec); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, &sec); err != nil {
		t.Fatal(err)
	}

	if err := r.Get(ctx, client.ObjectKeyFromObject(inst), got); err != nil {
		t.Fatal(err)
	}
	result, err := runReconcileInstance(ctx, r, got)
	if err != nil {
		t.Fatalf("a lost Secret must not be an error (it would retry with backoff forever), got %v", err)
	}
	if result.RequeueAfter != 30*time.Second {
		t.Fatalf("RequeueAfter = %s, want a 30s poll", result.RequeueAfter)
	}

	after := &dbaasv1.DBInstance{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(inst), after); err != nil {
		t.Fatal(err)
	}
	cond := after.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != string(dbaasv1.ReasonCredentialsLost) {
		t.Fatalf("CredentialsReady = %+v, want False/CredentialsLost", cond)
	}
	if !after.Status.IsConditionTrue(dbaasv1.ConditionInterventionRequired) {
		t.Fatal("InterventionRequired should be True so an admin is alerted")
	}
	// The database itself is untouched and still reported as available.
	if after.Status.Phase != dbaasv1.StatusAvailable || !after.Status.IsConditionTrue(dbaasv1.ConditionReady) {
		t.Fatalf("phase = %q Ready = %+v; the running database must stay available", after.Status.Phase, after.Status.GetCondition(dbaasv1.ConditionReady))
	}
	if err := r.Get(ctx, key, &sec); err == nil {
		t.Fatal("a replacement credentials Secret was generated")
	}
	if stub.CreateVMCalls != 1 {
		t.Fatalf("CreateVMCalls = %d, want still 1 (no VM rebuilt with a new password)", stub.CreateVMCalls)
	}
	warnings := 0
	for _, e := range drainRecorder(r) {
		if strings.Contains(e, "Warning") && strings.Contains(e, "CredentialsLost") {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("CredentialsLost warning events = %d, want 1", warnings)
	}
}

// End to end: the user's password is what reaches the VM's cloud-init, the
// status records where it came from, and the user's Secret is left alone.
func TestReconcileBYOPasswordReachesCloudInitAndStatus(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Spec.Credentials = &dbaasv1.CredentialsSpec{
		PasswordSource: dbaasv1.PasswordSource{SecretRef: dbaasv1.PasswordSecretRef{Name: "orders-pw", Key: "password"}},
	}
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "orders-pw", UID: "src-uid", ResourceVersion: "42"},
		Type:       dbaasv1.PasswordSecretType,
		Data:       map[string][]byte{"password": []byte(userChosenPassword)},
	}
	stub := availableStub()
	r := newProvisionReconciler(t, stub, inst, source)

	// Run until the VM has been created, then look at the cloud-init Secret
	// before bootstrap cleanup redacts it.
	key := client.ObjectKeyFromObject(inst)
	for pass := 1; pass <= 4 && stub.CreateVMCalls == 0; pass++ {
		if err := r.Get(ctx, key, inst); err != nil {
			t.Fatal(err)
		}
		if _, err := runReconcileInstance(ctx, r, inst); err != nil {
			t.Fatalf("pass %d: %v", pass, err)
		}
	}
	ensureVMObject(t, ctx, r, stub)
	if stub.CreateVMCalls != 1 {
		t.Fatalf("CreateVMCalls = %d, want 1", stub.CreateVMCalls)
	}
	var ci corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-cloudinit"}, &ci); err != nil {
		t.Fatal(err)
	}
	if want := "MASTER_PASSWORD='" + userChosenPassword + "'"; !strings.Contains(string(ci.Data["userdata"]), want) {
		t.Fatalf("cloud-init userdata does not carry the user's password (%q not found)", want)
	}

	got := walkToAvailable(t, ctx, r, inst, stub)

	c := got.Status.Credentials
	if c == nil || c.Source != dbaasv1.CredentialsSourceUserProvidedSecret || c.SourceSecretName != "orders-pw" ||
		c.SourceUID != "src-uid" || c.SourceResourceVersion != "42" || c.SourceChanged {
		t.Fatalf("status.credentials = %+v", c)
	}

	var tenant corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-credentials"}, &tenant); err != nil {
		t.Fatal(err)
	}
	if tenant.StringData["admin_password"] != userChosenPassword {
		t.Fatal("the saved copy does not hold the user's password")
	}

	// The user's Secret is untouched: same content, no owner, not deleted.
	var src corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "orders-pw"}, &src); err != nil {
		t.Fatalf("the user's Secret was deleted: %v", err)
	}
	if string(src.Data["password"]) != userChosenPassword || len(src.OwnerReferences) != 0 {
		t.Fatalf("the user's Secret was modified: %+v", src)
	}
}

// Editing the user's Secret after the database is available is reported once and
// changes nothing else: the phase, the saved password and the instance's
// requeue behaviour stay exactly as they were.
func TestReconcileChangedBYOSourceIsReportedWithoutDisturbingTheDatabase(t *testing.T) {
	ctx := context.Background()
	inst := newProvisionInst()
	inst.Spec.Credentials = &dbaasv1.CredentialsSpec{
		PasswordSource: dbaasv1.PasswordSource{SecretRef: dbaasv1.PasswordSecretRef{Name: "orders-pw", Key: "password"}},
	}
	source := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "orders-pw", UID: "src-uid", ResourceVersion: "42"},
		Type:       dbaasv1.PasswordSecretType,
		Data:       map[string][]byte{"password": []byte(userChosenPassword)},
	}
	stub := availableStub()
	r := newProvisionReconciler(t, stub, inst, source)
	walkToAvailable(t, ctx, r, inst, stub)
	drainRecorder(r)

	var live corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "orders-pw"}, &live); err != nil {
		t.Fatal(err)
	}
	live.Data["password"] = []byte("edited-after-the-database-was-available")
	if err := r.Update(ctx, &live); err != nil {
		t.Fatal(err)
	}

	key := client.ObjectKeyFromObject(inst)
	for pass := 1; pass <= 3; pass++ {
		got := &dbaasv1.DBInstance{}
		if err := r.Get(ctx, key, got); err != nil {
			t.Fatal(err)
		}
		result, err := runReconcileInstance(ctx, r, got)
		if err != nil || result != (ctrl.Result{}) {
			t.Fatalf("pass %d = (%+v, %v), want a quiet zero result", pass, result, err)
		}
	}

	after := &dbaasv1.DBInstance{}
	if err := r.Get(ctx, key, after); err != nil {
		t.Fatal(err)
	}
	if after.Status.Credentials == nil || !after.Status.Credentials.SourceChanged {
		t.Fatalf("status.credentials = %+v, want SourceChanged=true persisted", after.Status.Credentials)
	}
	if after.Status.Phase != dbaasv1.StatusAvailable || !after.Status.IsConditionTrue(dbaasv1.ConditionReady) {
		t.Fatalf("phase = %q; a changed source must not disturb the database", after.Status.Phase)
	}
	if cond := after.Status.GetCondition(dbaasv1.ConditionCredentialsReady); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("CredentialsReady = %+v, want True", cond)
	}
	var tenant corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-a", Name: "pg-orders-credentials"}, &tenant); err != nil {
		t.Fatal(err)
	}
	if tenant.StringData["admin_password"] != userChosenPassword {
		t.Fatal("the accepted password changed after the source was edited")
	}

	warnings := 0
	for _, e := range drainRecorder(r) {
		if strings.Contains(e, "Warning") && strings.Contains(e, "PasswordSourceChanged") {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("PasswordSourceChanged warning events over 3 passes = %d, want 1", warnings)
	}
}
