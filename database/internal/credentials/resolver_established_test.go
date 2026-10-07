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
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
)

func establishedAlways(context.Context, *dbaasv1.DBInstance) (bool, error) { return true, nil }

func deleteSecret(t *testing.T, r *Resolver, namespace, name string) {
	t.Helper()
	sec, ok := getSecret(t, r, namespace, name)
	if !ok {
		t.Fatalf("Secret %s/%s does not exist", namespace, name)
	}
	if err := r.Client.Delete(context.Background(), sec); err != nil {
		t.Fatal(err)
	}
}

// For an instance whose VM exists, a missing credentials Secret must never be
// replaced — whether the instance used a generated or a user-provided password.
func TestResolveRefusesToRegenerateTheCredentialsSecretOfAnEstablishedInstance(t *testing.T) {
	cases := []struct {
		name string
		inst func() *dbaasv1.DBInstance
		objs []client.Object
	}{
		{"generated", testInst, nil},
		{"user-provided", func() *dbaasv1.DBInstance { return byoInst("orders-pw", "password") },
			[]client.Object{goodSecret(byoPassword)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			inst := tc.inst()
			r := resolverWith(t, tc.objs...)
			if _, err := r.Resolve(ctx, inst); err != nil { // first-time provisioning
				t.Fatal(err)
			}
			r.Established = establishedAlways
			deleteSecret(t, r, "tenant-a", "pg-orders-credentials")

			_, err := r.Resolve(ctx, inst)

			if !errors.Is(err, ErrCredentialsLost) {
				t.Fatalf("err = %v, want ErrCredentialsLost", err)
			}
			var lost *CredentialsLostError
			if !errors.As(err, &lost) || lost.Namespace != "tenant-a" || lost.Name != "pg-orders-credentials" {
				t.Fatalf("error does not name the missing Secret: %#v", err)
			}
			if _, ok := getSecret(t, r, "tenant-a", "pg-orders-credentials"); ok {
				t.Fatal("a replacement credentials Secret was generated")
			}
		})
	}
}

// The lost-credentials hazard for a user-provided password: if the source was
// edited since provisioning, re-reading it would snapshot a password the
// database does not have. An established instance must not even look.
func TestResolveEstablishedInstanceNeverRereadsTheEditedSource(t *testing.T) {
	ctx := context.Background()
	inst := byoInst("orders-pw", "password")
	r := resolverWith(t, goodSecret(byoPassword))
	if _, err := r.Resolve(ctx, inst); err != nil {
		t.Fatal(err)
	}

	src, _ := getSecret(t, r, "tenant-a", "orders-pw")
	src.Data["password"] = []byte("edited-after-provisioning")
	if err := r.Client.Update(ctx, src); err != nil {
		t.Fatal(err)
	}
	deleteSecret(t, r, "tenant-a", "pg-orders-credentials")

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
	r.Established = establishedAlways

	if _, err := r.Resolve(ctx, inst); !errors.Is(err, ErrCredentialsLost) {
		t.Fatalf("err = %v, want ErrCredentialsLost", err)
	}
	if sourceReads != 0 {
		t.Fatalf("the user's Secret was read %d times for an established instance, want 0", sourceReads)
	}
}

// The platform-owned Secrets follow the same rule: a regenerated CA or exporter
// password would not match the running VM.
func TestResolveRefusesToRegenerateInternalOrTLSOfAnEstablishedInstance(t *testing.T) {
	for _, tc := range []struct {
		what string
		name func(*dbaasv1.DBInstance) string
	}{
		{"internal credentials", InternalSecretName},
		{"TLS", TLSSecretName},
	} {
		t.Run(tc.what, func(t *testing.T) {
			ctx := context.Background()
			inst := testInst()
			r := newTestResolver(t)
			if _, err := r.Resolve(ctx, inst); err != nil {
				t.Fatal(err)
			}
			r.Established = establishedAlways
			deleteSecret(t, r, "dbaas-system", tc.name(inst))

			_, err := r.Resolve(ctx, inst)

			var lost *CredentialsLostError
			if !errors.As(err, &lost) || lost.Name != tc.name(inst) {
				t.Fatalf("err = %v, want CredentialsLostError for %s", err, tc.name(inst))
			}
			if _, ok := getSecret(t, r, "dbaas-system", tc.name(inst)); ok {
				t.Fatalf("%s was regenerated", tc.name(inst))
			}
		})
	}
}

// Before the VM exists, behavior is unchanged: missing material is created, and
// a partial state is repaired without rotating what is already there.
func TestResolveStillCreatesAndRepairsMaterialBeforeTheVMExists(t *testing.T) {
	ctx := context.Background()
	inst := testInst()
	r := newTestResolver(t)
	r.Established = func(context.Context, *dbaasv1.DBInstance) (bool, error) { return false, nil }

	first, err := r.Resolve(ctx, inst)
	if err != nil || !first.Changed {
		t.Fatalf("first Resolve: Changed=%t err=%v", first.Changed, err)
	}
	deleteSecret(t, r, "dbaas-system", InternalSecretName(inst))

	second, err := r.Resolve(ctx, inst)
	if err != nil || !second.Changed {
		t.Fatalf("repair Resolve: Changed=%t err=%v", second.Changed, err)
	}
	if second.Material.AdminPassword != first.Material.AdminPassword {
		t.Fatal("repairing the internal Secret rotated the admin password")
	}
}

// The guard only runs when something is missing: an instance whose Secrets all
// exist must resolve normally, without even asking whether it is established.
func TestResolveDoesNotConsultEstablishedWhenNothingIsMissing(t *testing.T) {
	ctx := context.Background()
	inst := testInst()
	r := newTestResolver(t)
	if _, err := r.Resolve(ctx, inst); err != nil {
		t.Fatal(err)
	}
	asked := 0
	r.Established = func(context.Context, *dbaasv1.DBInstance) (bool, error) { asked++; return true, nil }

	got, err := r.Resolve(ctx, inst)
	if err != nil || got.Changed {
		t.Fatalf("Resolve: Changed=%t err=%v", got.Changed, err)
	}
	if asked != 0 {
		t.Fatalf("Established was consulted %d times with nothing missing, want 0", asked)
	}
}

// If the resolver cannot tell whether the instance is established, it must not
// guess: no replacement is generated, and the error says why.
func TestResolveEstablishedLookupErrorCreatesNothing(t *testing.T) {
	boom := errors.New("apiserver unavailable")
	inst := testInst()
	r := newTestResolver(t)
	r.Established = func(context.Context, *dbaasv1.DBInstance) (bool, error) { return false, boom }

	_, err := r.Resolve(context.Background(), inst)

	if !errors.Is(err, boom) || errors.Is(err, ErrCredentialsLost) {
		t.Fatalf("err = %v, want the lookup error and not ErrCredentialsLost", err)
	}
	for _, key := range [][2]string{
		{"tenant-a", "pg-orders-credentials"}, {"dbaas-system", InternalSecretName(inst)}, {"dbaas-system", TLSSecretName(inst)},
	} {
		if _, ok := getSecret(t, r, key[0], key[1]); ok {
			t.Errorf("Secret %s/%s was created", key[0], key[1])
		}
	}
}

func TestCredentialsLostErrorNamesTheSecretButNoValues(t *testing.T) {
	msg := (&CredentialsLostError{Namespace: "tenant-a", Name: "pg-orders-credentials"}).Error()
	for _, want := range []string{"tenant-a/pg-orders-credentials", "will not generate a replacement", "Restore"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q missing %q", msg, want)
		}
	}
}
