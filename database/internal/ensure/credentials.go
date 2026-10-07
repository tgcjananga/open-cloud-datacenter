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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
	"github.com/wso2/open-cloud-datacenter/crds/dbaas/internal/credentials"
)

const credentialRequeue = 5 * time.Second

// credentialSourceRequeue is how often to look again while the user's password
// Secret is missing or unusable, or while a lost durable Secret waits to be
// restored. Nothing watches those Secrets, so this poll is how a fix is noticed.
const credentialSourceRequeue = 30 * time.Second

type credentialsStep struct{ Dependencies }

func newCredentialsStep(deps Dependencies) Step { return &credentialsStep{Dependencies: deps} }

func (*credentialsStep) Name() string { return "credentials" }

// ensureCredentials resolves the durable credential/TLS material: the
// tenant admin-credentials Secret, and the two operator-namespace private
// Secrets (internal DB credentials, TLS). Material is generated at most once
// per Secret — re-resolving on later passes only reads what already exists,
// preserving the reuse-on-reentry invariant (a regenerated password/CA would
// diverge from an already-booted VM). Creation stops this pass so the next pass
// re-observes the persisted material before ensureVM is allowed to proceed.
func (r *credentialsStep) Run(ctx context.Context, inst *dbaasv1.DBInstance) Result {
	result, err := r.credentialsResolver().Resolve(ctx, inst)
	if err != nil {
		return r.resolveFailed(inst, err)
	}

	opNS := r.operatorNamespace()
	inst.Status.Resources.AdminCredentialsSecretName = credentials.TenantCredentialsSecretName(inst)
	inst.Status.Resources.InternalSecretRef = fmt.Sprintf("%s/%s", opNS, credentials.InternalSecretName(inst))
	inst.Status.Resources.PrivateTLSSecretRef = fmt.Sprintf("%s/%s", opNS, credentials.TLSSecretName(inst))
	recordCredentialsSource(inst, result.Source)
	if result.Changed {
		msg := "credential material created; waiting for observation"
		inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionTrue,
			dbaasv1.ReasonCredentialsCreated, msg)
		// PendingAfter() is used here since cross-namespace owner references is not allowed
		return PendingAfter(dbaasv1.ReasonCredentialsCreated, msg, credentialRequeue)
	}

	inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionTrue,
		dbaasv1.ReasonCredentialsProvisioned, "admin credentials and private material observed")
	return Satisfied()
}

// recordCredentialsSource publishes where the accepted master password came
// from. It updates the fields in place rather than replacing the struct, so
// SourceChanged — set by the source-change check, not by resolution — survives
// every pass.
func recordCredentialsSource(inst *dbaasv1.DBInstance, src credentials.SourceInfo) {
	if inst.Status.Credentials == nil {
		inst.Status.Credentials = &dbaasv1.CredentialsStatus{}
	}
	st := inst.Status.Credentials
	st.Source = src.Source
	st.SourceSecretName = src.SecretName
	st.SourceUID = src.SecretUID
	st.SourceResourceVersion = src.ResourceVersion
}

// resolveFailed turns a Resolve error into a condition and a step result. The
// three credential-specific errors are conditions the user or an admin can fix,
// so they poll slowly instead of retrying with backoff; anything else is an
// ordinary transient failure.
func (r *credentialsStep) resolveFailed(inst *dbaasv1.DBInstance, err error) Result {
	switch {
	case errors.Is(err, credentials.ErrCredentialsLost):
		msg := err.Error()
		previous := inst.Status.GetCondition(dbaasv1.ConditionCredentialsReady)
		firstTime := previous == nil || previous.Reason != string(dbaasv1.ReasonCredentialsLost)
		inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionFalse,
			dbaasv1.ReasonCredentialsLost, msg)
		if firstTime { // not on every poll
			r.Recorder.Eventf(inst, corev1.EventTypeWarning, string(dbaasv1.ReasonCredentialsLost), "%s", msg)
		}
		return PendingAfter(dbaasv1.ReasonCredentialsLost, msg, credentialSourceRequeue)

	case errors.Is(err, credentials.ErrPasswordSourceNotFound):
		msg := err.Error()
		inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionFalse,
			dbaasv1.ReasonPasswordSourceNotFound, msg)
		return PendingAfter(dbaasv1.ReasonPasswordSourceNotFound, msg, credentialSourceRequeue)

	case errors.Is(err, credentials.ErrPasswordSourceInvalid):
		msg := err.Error()
		inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionFalse,
			dbaasv1.ReasonPasswordSourceInvalid, msg)
		return PendingAfter(dbaasv1.ReasonPasswordSourceInvalid, msg, credentialSourceRequeue)

	default:
		inst.SetCurrentCondition(dbaasv1.ConditionCredentialsReady, metav1.ConditionFalse,
			dbaasv1.ReasonCredentialsResolveFailed, err.Error())
		return Transient(err)
	}
}

// instanceEstablished reports whether the instance's VM has ever been created,
// which is when its durable credentials stop being replaceable. It is
// deliberately not "cloud-init Secret or VM name is recorded": both are
// written before CreatePostgresVM runs, so a create that failed outright leaves
// them behind with no VM and no database to protect.
//
// status.appliedSpec is the durable fact — it is set only after a successful
// create. The live VM lookup covers the one gap: a crash after the VM was
// created but before that status was saved.
func (d Dependencies) instanceEstablished(ctx context.Context, inst *dbaasv1.DBInstance) (bool, error) {
	if inst.Status.AppliedSpec != nil {
		return true, nil
	}
	var vm kubevirtv1.VirtualMachine
	err := d.Get(ctx, types.NamespacedName{Namespace: inst.Namespace, Name: vmNameFor(inst)}, &vm)
	switch {
	case err == nil:
		return true, nil
	case apierrors.IsNotFound(err):
		return false, nil
	default:
		return false, err
	}
}
