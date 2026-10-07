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
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
)

const byoPassword = `it's"a$HOME\path:x and spaces`

func getSecret(t *testing.T, r *Resolver, namespace, name string) (*corev1.Secret, bool) {
	t.Helper()
	var sec corev1.Secret
	err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, &sec)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("get %s/%s: %v", namespace, name, err)
	}
	return &sec, true
}

func TestResolveBYOKeepsTheAcceptedPasswordInTheCredentialsSecret(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	inst.Spec.MasterUsername = "orders_admin"
	r := resolverWith(t, goodSecret(byoPassword))

	result, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !result.Changed {
		t.Fatal("first Resolve reported Changed=false")
	}
	if result.Material.AdminUser != "orders_admin" || result.Material.AdminPassword != byoPassword {
		t.Fatalf("Material = user %q password %q", result.Material.AdminUser, result.Material.AdminPassword)
	}
	wantSource := SourceInfo{
		Source:          dbaasv1.CredentialsSourceUserProvidedSecret,
		SecretName:      "orders-pw",
		SecretUID:       "src-uid",
		ResourceVersion: "42",
	}
	if result.Source != wantSource {
		t.Fatalf("Source = %+v, want %+v", result.Source, wantSource)
	}

	// The accepted password is persisted in the credentials Secret, with the
	// source identity as annotations, controller-owned like a generated one.
	tenant, ok := getSecret(t, r, "tenant-a", "pg-orders-credentials")
	if !ok {
		t.Fatal("credentials Secret was not created")
	}
	if tenant.StringData["admin_user"] != "orders_admin" || tenant.StringData["admin_password"] != byoPassword {
		t.Fatalf("credentials Secret contents = %+v", tenant.StringData)
	}
	for k, want := range map[string]string{
		dbaasv1.AnnotationPasswordSourceSecret:          "orders-pw",
		dbaasv1.AnnotationPasswordSourceUID:             "src-uid",
		dbaasv1.AnnotationPasswordSourceResourceVersion: "42",
	} {
		if got := tenant.Annotations[k]; got != want {
			t.Errorf("annotation %s = %q, want %q", k, got, want)
		}
	}
	if refs := tenant.GetOwnerReferences(); len(refs) != 1 || refs[0].Controller == nil || !*refs[0].Controller {
		t.Fatalf("credentials Secret owner refs = %+v, want controller-owned", refs)
	}
	// No annotation or label may carry the password or anything derived from it.
	for k, v := range tenant.Annotations {
		if v == byoPassword {
			t.Errorf("annotation %s holds the password", k)
		}
	}

	// The platform Secrets are still created, exactly as for a generated password.
	if _, ok := getSecret(t, r, "dbaas-system", InternalSecretName(inst)); !ok {
		t.Error("internal Secret missing")
	}
	if _, ok := getSecret(t, r, "dbaas-system", TLSSecretName(inst)); !ok {
		t.Error("TLS Secret missing")
	}

	// The user's own Secret is untouched.
	src, ok := getSecret(t, r, "tenant-a", "orders-pw")
	if !ok || string(src.Data["password"]) != byoPassword || src.ResourceVersion != "42" {
		t.Fatalf("source Secret was modified or deleted: %+v", src)
	}
	if len(src.OwnerReferences) != 0 {
		t.Fatalf("source Secret must not gain an owner reference: %+v", src.OwnerReferences)
	}
}

func TestResolveBYOEditingTheSourceAfterwardsDoesNotChangeTheAcceptedPassword(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	r := resolverWith(t, goodSecret(byoPassword))

	first, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}

	src, _ := getSecret(t, r, "tenant-a", "orders-pw")
	src.Data["password"] = []byte("a-completely-different-password")
	if err := r.Client.Update(ctx, src); err != nil {
		t.Fatal(err)
	}

	second, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatal("re-resolve after a source edit reported a mutation")
	}
	if second.Material.AdminPassword != byoPassword || second.Material.AdminPassword != first.Material.AdminPassword {
		t.Fatalf("accepted password changed after the source was edited: %q", second.Material.AdminPassword)
	}
	// The recorded identity is the one from acceptance time, not the edited Secret's.
	if second.Source != first.Source {
		t.Fatalf("Source changed: %+v -> %+v", first.Source, second.Source)
	}
}

func TestResolveBYODeletingTheSourceAfterwardsStillWorks(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	r := resolverWith(t, goodSecret(byoPassword))
	if _, err := r.Resolve(ctx, inst); err != nil {
		t.Fatal(err)
	}

	src, _ := getSecret(t, r, "tenant-a", "orders-pw")
	if err := r.Client.Delete(ctx, src); err != nil {
		t.Fatal(err)
	}

	got, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatalf("Resolve after the source was deleted: %v", err)
	}
	if got.Changed || got.Material.AdminPassword != byoPassword {
		t.Fatalf("got Changed=%t password %q", got.Changed, got.Material.AdminPassword)
	}
}

// Once the password is accepted, later passes must not touch the user's Secret
// at all — that is what makes it a creation-time input.
func TestResolveBYONeverReadsTheSourceAgainOnceAccepted(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	r := resolverWith(t, goodSecret(byoPassword))
	if _, err := r.Resolve(ctx, inst); err != nil {
		t.Fatal(err)
	}

	sourceReads := 0
	watch, ok := r.Client.(client.WithWatch)
	if !ok {
		t.Fatal("fake client does not implement client.WithWatch")
	}
	r.Client = interceptor.NewClient(watch, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if key.Name == "orders-pw" {
				sourceReads++
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	for i := 0; i < 3; i++ {
		if _, err := r.Resolve(ctx, inst); err != nil {
			t.Fatal(err)
		}
	}
	if sourceReads != 0 {
		t.Fatalf("source Secret was read %d times after acceptance, want 0", sourceReads)
	}
}

// A missing or unusable source must fail before anything is created: no
// credentials Secret, and none of the platform Secrets either.
func TestResolveBYOUnusableSourceCreatesNothing(t *testing.T) {
	cases := []struct {
		name    string
		objects []client.Object
		mutate  func(*dbaasv1.DBInstance)
		want    error
	}{
		{"source missing", nil, nil, ErrPasswordSourceNotFound},
		{"password too short", []client.Object{goodSecret("short")}, nil, ErrPasswordSourceInvalid},
		{"wrong Secret type", []client.Object{byoSecret("tenant-a", "orders-pw", corev1.SecretTypeOpaque,
			map[string][]byte{"password": []byte("long-enough-password")})}, nil, ErrPasswordSourceInvalid},
		{"reserved master username", []client.Object{goodSecret("long-enough-password")},
			func(i *dbaasv1.DBInstance) { i.Spec.MasterUsername = "postgres" }, ErrPasswordSourceInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst := byoInst("orders-pw", "password")
			if tc.mutate != nil {
				tc.mutate(inst)
			}
			r := resolverWith(t, tc.objects...)

			_, err := r.Resolve(context.Background(), inst)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, ok := getSecret(t, r, "tenant-a", "pg-orders-credentials"); ok {
				t.Error("credentials Secret was created")
			}
			if _, ok := getSecret(t, r, "dbaas-system", InternalSecretName(inst)); ok {
				t.Error("internal Secret was created")
			}
			if _, ok := getSecret(t, r, "dbaas-system", TLSSecretName(inst)); ok {
				t.Error("TLS Secret was created")
			}
		})
	}
}

// If two reconciles race to create the credentials Secret, both must end up
// using the persisted winner — never an in-memory candidate that was not saved.
func TestResolveBYOAdoptsTheRaceWinner(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	r := resolverWith(t, goodSecret(byoPassword))
	watch, ok := r.Client.(client.WithWatch)
	if !ok {
		t.Fatal("fake client does not implement client.WithWatch")
	}
	const winnerPassword = "winner-password-from-another-reconcile"
	intercepted := false
	r.Client = interceptor.NewClient(watch, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			sec, isSecret := obj.(*corev1.Secret)
			if !intercepted && isSecret && sec.Name == TenantCredentialsSecretName(inst) {
				intercepted = true
				winner := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: sec.Name, Namespace: sec.Namespace,
						Annotations: map[string]string{
							dbaasv1.AnnotationPasswordSourceSecret:          "orders-pw",
							dbaasv1.AnnotationPasswordSourceUID:             "winner-uid",
							dbaasv1.AnnotationPasswordSourceResourceVersion: "7",
						},
					},
					StringData: map[string]string{"admin_user": "dbadmin", "admin_password": winnerPassword},
				}
				if err := c.Create(ctx, winner); err != nil {
					return err
				}
				return apierrors.NewAlreadyExists(schema.GroupResource{Resource: "secrets"}, sec.Name)
			}
			return c.Create(ctx, obj, opts...)
		},
	})

	result, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Material.AdminPassword != winnerPassword {
		t.Fatalf("result = %+v, want Changed with the race winner's password", result.Material)
	}
	if result.Source.SecretUID != "winner-uid" || result.Source.ResourceVersion != "7" {
		t.Fatalf("Source = %+v, want the winner's recorded identity", result.Source)
	}
}

// Instances without spec.credentials behave exactly as before: a generated
// password, and no source annotations.
func TestResolveGeneratedPasswordIsUnchangedAndMarkedGenerated(t *testing.T) {
	ctx := context.Background()
	inst := testInst()
	r := newTestResolver(t)

	result, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Material.AdminPassword) != 32 {
		t.Fatalf("generated password length = %d, want 32", len(result.Material.AdminPassword))
	}
	if result.Source != (SourceInfo{Source: dbaasv1.CredentialsSourceGenerated}) {
		t.Fatalf("Source = %+v, want Generated with no Secret identity", result.Source)
	}
	tenant, _ := getSecret(t, r, "tenant-a", "pg-orders-credentials")
	if len(tenant.Annotations) != 0 {
		t.Fatalf("generated credentials Secret has annotations: %v", tenant.Annotations)
	}

	again, err := r.Resolve(ctx, inst)
	if err != nil || again.Changed || again.Source != result.Source {
		t.Fatalf("re-resolve: Changed=%t Source=%+v err=%v", again.Changed, again.Source, err)
	}
}

// A credentials Secret that predates user-provided passwords has no source
// annotations. If the spec now names a source (possible only if the API field
// was accepted by an older controller that ignored it), the existing password
// is kept — the database already has it — and status reports it truthfully as
// Generated rather than claiming the user's Secret was used.
func TestResolveExistingGeneratedSecretIsNeverReplacedByASource(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "pg-orders-credentials"},
		Data:       map[string][]byte{"admin_user": []byte("dbadmin"), "admin_password": []byte("already-in-the-database")},
	}
	r := resolverWith(t, existing, goodSecret(byoPassword))

	got, err := r.Resolve(ctx, inst)
	if err != nil {
		t.Fatal(err)
	}
	if got.Material.AdminPassword != "already-in-the-database" {
		t.Fatalf("existing password was replaced by the source: %q", got.Material.AdminPassword)
	}
	if got.Source.Source != dbaasv1.CredentialsSourceGenerated {
		t.Fatalf("Source = %+v, want Generated (the truth about what the database has)", got.Source)
	}
}
