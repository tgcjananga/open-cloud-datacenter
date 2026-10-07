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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
)

func byoInst(secret, key string) *dbaasv1.DBInstance {
	inst := testInst()
	inst.Spec.Credentials = &dbaasv1.CredentialsSpec{
		PasswordSource: dbaasv1.PasswordSource{SecretRef: dbaasv1.PasswordSecretRef{Name: secret, Key: key}},
	}
	return inst
}

func byoSecret(namespace, name string, typ corev1.SecretType, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			UID: types.UID("src-uid"), ResourceVersion: "42",
		},
		Type: typ,
		Data: data,
	}
}

func resolverWith(t *testing.T, objs ...client.Object) *Resolver {
	t.Helper()
	scheme := testScheme(t)
	return &Resolver{
		Client:            ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build(),
		Scheme:            scheme,
		OperatorNamespace: "dbaas-system",
		DefaultMasterUser: testDefaultMasterUser,
	}
}

func goodSecret(password string) *corev1.Secret {
	return byoSecret("tenant-a", "orders-pw", dbaasv1.PasswordSecretType,
		map[string][]byte{"password": []byte(password)})
}

func TestResolvePasswordSourceReturnsThePasswordUnchanged(t *testing.T) {
	passwords := []string{
		"plain-password-1",
		`it's"a$HOME\path:x`,
		"back`tick`s and $(subshell)",
		`semi;colon && pipe | amp & hash #`,
		"  leading and trailing spaces  ",
		`colon:and\backslash\:mix`,
		"%I %L %s %d",
		"EOSQL-EOSQL",
		`'; DROP ROLE postgres; --`,
		"ünïcödé-密码-🔑",
		strings.Repeat("x", MinPasswordBytes),
		strings.Repeat("x", MaxPasswordBytes),
	}
	for _, pw := range passwords {
		r := resolverWith(t, goodSecret(pw))
		got, err := r.ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
		if err != nil {
			t.Errorf("password %q: %v", pw, err)
			continue
		}
		if got.Password != pw {
			t.Errorf("password changed: got %q, want %q", got.Password, pw)
		}
		if got.SecretUID != "src-uid" || got.ResourceVersion != "42" {
			t.Errorf("source identity = %q/%q, want src-uid/42", got.SecretUID, got.ResourceVersion)
		}
	}
}

func TestResolvePasswordSourceReadsStringDataToo(t *testing.T) {
	sec := byoSecret("tenant-a", "orders-pw", dbaasv1.PasswordSecretType, nil)
	sec.StringData = map[string]string{"password": "from-string-data"}
	got, err := resolverWith(t, sec).ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
	if err != nil || got.Password != "from-string-data" {
		t.Fatalf("got %q, %v", got.Password, err)
	}
}

func TestResolvePasswordSourceMissingSecretIsRetryableNotFound(t *testing.T) {
	_, err := resolverWith(t).ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
	if !errors.Is(err, ErrPasswordSourceNotFound) {
		t.Fatalf("err = %v, want ErrPasswordSourceNotFound", err)
	}
	if errors.Is(err, ErrPasswordSourceInvalid) {
		t.Fatal("a missing Secret must not also read as invalid")
	}
	var pe *PasswordSourceError
	if !errors.As(err, &pe) || pe.Name != "orders-pw" || pe.Namespace != "tenant-a" {
		t.Fatalf("error does not name the Secret: %#v", err)
	}
}

func TestResolvePasswordSourceDoesNotReadOtherNamespaces(t *testing.T) {
	// Same name, different namespace: must not be found.
	other := byoSecret("tenant-b", "orders-pw", dbaasv1.PasswordSecretType,
		map[string][]byte{"password": []byte("belongs-to-tenant-b")})
	_, err := resolverWith(t, other).ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
	if !errors.Is(err, ErrPasswordSourceNotFound) {
		t.Fatalf("err = %v, want ErrPasswordSourceNotFound (no cross-namespace lookup)", err)
	}
}

func TestResolvePasswordSourceRejectsUnusableSecrets(t *testing.T) {
	const marker = "SECRETMARKER"
	cases := []struct {
		name     string
		secret   *corev1.Secret
		key      string
		wantText string
	}{
		{"wrong type Opaque", byoSecret("tenant-a", "orders-pw", corev1.SecretTypeOpaque,
			map[string][]byte{"password": []byte("long-enough-" + marker)}), "password", "has type"},
		{"wrong type TLS", byoSecret("tenant-a", "orders-pw", corev1.SecretTypeTLS,
			map[string][]byte{"password": []byte("long-enough-" + marker)}), "password", "has type"},
		{"missing key", goodSecret("long-enough-" + marker), "nope", "not present"},
		{"empty value", goodSecret(""), "password", "empty"},
		{"too short", goodSecret("S3cr3t!"), "password", "minimum is 8"},
		{"too long", goodSecret(strings.Repeat("x", MaxPasswordBytes) + marker), "password", "maximum is 128"},
		{"contains LF", goodSecret("good-prefix\n" + marker), "password", "line break"},
		{"trailing LF", goodSecret("good-password-" + marker + "\n"), "password", "line break"},
		{"contains CR", goodSecret("good-prefix\r" + marker), "password", "line break"},
		{"contains NUL", goodSecret("good-prefix\x00" + marker), "password", "NUL"},
		{"invalid UTF-8", goodSecret("\xff\xfe-" + marker), "password", "UTF-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolverWith(t, tc.secret).ResolvePasswordSource(context.Background(), byoInst("orders-pw", tc.key))
			if !errors.Is(err, ErrPasswordSourceInvalid) {
				t.Fatalf("err = %v, want ErrPasswordSourceInvalid", err)
			}
			if errors.Is(err, ErrPasswordSourceNotFound) {
				t.Fatal("an unusable Secret must not read as not found")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error %q does not mention %q", err, tc.wantText)
			}
			if strings.Contains(err.Error(), marker) {
				t.Errorf("error leaks part of the password: %q", err)
			}
		})
	}
}

func TestValidatePasswordBoundaries(t *testing.T) {
	for _, n := range []int{MinPasswordBytes, MinPasswordBytes + 1, MaxPasswordBytes - 1, MaxPasswordBytes} {
		if err := ValidatePassword(strings.Repeat("a", n)); err != nil {
			t.Errorf("%d bytes rejected: %v", n, err)
		}
	}
	for _, n := range []int{0, 1, MinPasswordBytes - 1, MaxPasswordBytes + 1} {
		if err := ValidatePassword(strings.Repeat("a", n)); err == nil {
			t.Errorf("%d bytes accepted", n)
		}
	}
	// The limit is in bytes, not characters: 4 four-byte runes are 16 bytes.
	if err := ValidatePassword(strings.Repeat("🔑", 4)); err != nil {
		t.Errorf("multi-byte password of 16 bytes rejected: %v", err)
	}
	if err := ValidatePassword(strings.Repeat("🔑", MaxPasswordBytes/4+1)); err == nil {
		t.Error("multi-byte password over the byte limit accepted")
	}
}

func TestResolvePasswordSourceRejectsReservedMasterUsernames(t *testing.T) {
	reserved := []string{"postgres", "POSTGRES", "Postgres", "postgres_exporter", "replicator", "repl",
		"public", "none", "pg_monitor", "pg_custom", "PG_anything"}
	for _, user := range reserved {
		inst := byoInst("orders-pw", "password")
		inst.Spec.MasterUsername = user
		_, err := resolverWith(t, goodSecret("long-enough-password")).ResolvePasswordSource(context.Background(), inst)
		if !errors.Is(err, ErrPasswordSourceInvalid) {
			t.Errorf("master username %q: err = %v, want ErrPasswordSourceInvalid", user, err)
		}
	}

	allowed := []string{"dbadmin", "orders_admin", "pgadmin", "pg", "postgres2", "app$user", "_svc"}
	for _, user := range allowed {
		inst := byoInst("orders-pw", "password")
		inst.Spec.MasterUsername = user
		if _, err := resolverWith(t, goodSecret("long-enough-password")).ResolvePasswordSource(context.Background(), inst); err != nil {
			t.Errorf("master username %q rejected: %v", user, err)
		}
	}
}

func TestResolvePasswordSourceChecksTheDefaultMasterUserToo(t *testing.T) {
	r := resolverWith(t, goodSecret("long-enough-password"))
	r.DefaultMasterUser = "postgres" // masterUsername omitted -> default applies
	_, err := r.ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
	if !errors.Is(err, ErrPasswordSourceInvalid) {
		t.Fatalf("err = %v, want ErrPasswordSourceInvalid", err)
	}
}

func TestResolvePasswordSourceWithoutCredentialsBlock(t *testing.T) {
	_, err := resolverWith(t).ResolvePasswordSource(context.Background(), testInst())
	if !errors.Is(err, ErrNoPasswordSource) {
		t.Fatalf("err = %v, want ErrNoPasswordSource", err)
	}
}

// An API failure other than NotFound (timeout, forbidden, ...) is transient:
// it must not be classified as "missing" or "invalid", which would turn a
// blip into a permanent failure or a wait-for-user condition.
func TestResolvePasswordSourceAPIFailureIsNeitherNotFoundNorInvalid(t *testing.T) {
	boom := errors.New("apiserver unavailable")
	scheme := testScheme(t)
	r := &Resolver{
		Client: ctrlfake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return boom
			},
		}).Build(),
		Scheme:            scheme,
		OperatorNamespace: "dbaas-system",
		DefaultMasterUser: testDefaultMasterUser,
	}
	_, err := r.ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the underlying API error", err)
	}
	if errors.Is(err, ErrPasswordSourceNotFound) || errors.Is(err, ErrPasswordSourceInvalid) {
		t.Fatal("an API failure must not be classified as not found or invalid")
	}
}

// The source Secret is the user's: resolving must never write to it.
func TestResolvePasswordSourceNeverModifiesTheSecret(t *testing.T) {
	sec := goodSecret("long-enough-password")
	writes := 0
	scheme := testScheme(t)
	r := &Resolver{
		Client: ctrlfake.NewClientBuilder().WithScheme(scheme).WithObjects(sec).WithInterceptorFuncs(interceptor.Funcs{
			Create: func(context.Context, client.WithWatch, client.Object, ...client.CreateOption) error {
				writes++
				return nil
			},
			Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
				writes++
				return nil
			},
			Patch: func(context.Context, client.WithWatch, client.Object, client.Patch, ...client.PatchOption) error {
				writes++
				return nil
			},
			Delete: func(context.Context, client.WithWatch, client.Object, ...client.DeleteOption) error {
				writes++
				return nil
			},
		}).Build(),
		Scheme:            scheme,
		OperatorNamespace: "dbaas-system",
		DefaultMasterUser: testDefaultMasterUser,
	}
	if _, err := r.ResolvePasswordSource(context.Background(), byoInst("orders-pw", "password")); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("ResolvePasswordSource made %d write calls, want 0", writes)
	}
}

// The Secret type is a guardrail against mistakes, not a security boundary:
// anyone who can write a Secret can give it this type. This test documents
// that, so nobody later reads the check as isolation.
func TestPasswordSecretTypeIsOnlyAGuardrail(t *testing.T) {
	forged := byoSecret("tenant-a", "service-account-token", dbaasv1.PasswordSecretType,
		map[string][]byte{"token": []byte("eyJhbGciOi-pretend-this-is-a-sa-token")})
	got, err := resolverWith(t, forged).ResolvePasswordSource(context.Background(), byoInst("service-account-token", "token"))
	if err != nil {
		t.Fatalf("a Secret carrying the right type is accepted by design, got %v", err)
	}
	if got.Password == "" {
		t.Fatal("expected the forged Secret's value to be returned")
	}
}

// Teardown deletes pg-<name>-credentials, -connect and -cloudinit by name, so a
// user's Secret carrying one of those names would be deleted with the
// instance. The name is therefore refused before anything is read.
func TestResolvePasswordSourceRefusesTheNamesOfSecretsDBaaSOwns(t *testing.T) {
	for _, owned := range []string{"pg-orders-credentials", "pg-orders-connect", "pg-orders-cloudinit"} {
		t.Run(owned, func(t *testing.T) {
			// The Secret exists and would otherwise be valid, so only the name can reject it.
			sec := byoSecret("tenant-a", owned, dbaasv1.PasswordSecretType,
				map[string][]byte{"password": []byte("long-enough-password")})
			reads := 0
			r := resolverWith(t, sec)
			watch, ok := r.Client.(client.WithWatch)
			if !ok {
				t.Fatal("fake client does not implement client.WithWatch")
			}
			r.Client = interceptor.NewClient(watch, interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					reads++
					return c.Get(ctx, key, obj, opts...)
				},
			})

			_, err := r.ResolvePasswordSource(context.Background(), byoInst(owned, "password"))

			if !errors.Is(err, ErrPasswordSourceInvalid) || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("err = %v, want ErrPasswordSourceInvalid mentioning a reserved name", err)
			}
			if reads != 0 {
				t.Fatalf("the Secret was read %d times; a reserved name must be refused before any read", reads)
			}
		})
	}
}

func TestResolvePasswordSourceAcceptsNamesThatOnlyLookSimilar(t *testing.T) {
	for _, name := range []string{"orders-pw", "pg-orders-credentials-backup", "my-pg-orders-credentials", "pg-orders-password"} {
		sec := byoSecret("tenant-a", name, dbaasv1.PasswordSecretType,
			map[string][]byte{"password": []byte("long-enough-password")})
		if _, err := resolverWith(t, sec).ResolvePasswordSource(context.Background(), byoInst(name, "password")); err != nil {
			t.Errorf("name %q rejected: %v", name, err)
		}
	}
}

// Resolve must not create anything for a colliding name either.
func TestResolveBYOWithAnOwnedSecretNameCreatesNothing(t *testing.T) {
	inst := byoInst("pg-orders-credentials", "password")
	sec := byoSecret("tenant-a", "pg-orders-credentials", dbaasv1.PasswordSecretType,
		map[string][]byte{"password": []byte("long-enough-password")})
	r := resolverWith(t, sec)

	_, err := r.Resolve(context.Background(), inst)

	if !errors.Is(err, ErrPasswordSourceInvalid) {
		t.Fatalf("err = %v, want ErrPasswordSourceInvalid", err)
	}
	for _, key := range [][2]string{{"dbaas-system", InternalSecretName(inst)}, {"dbaas-system", TLSSecretName(inst)}} {
		if _, ok := getSecret(t, r, key[0], key[1]); ok {
			t.Errorf("Secret %s/%s was created", key[0], key[1])
		}
	}
	// The user's Secret is exactly as it was: not adopted, not annotated, not owned.
	got, _ := getSecret(t, r, "tenant-a", "pg-orders-credentials")
	if len(got.Annotations) != 0 || len(got.OwnerReferences) != 0 || string(got.Data["password"]) != "long-enough-password" {
		t.Fatalf("the user's Secret was touched: %+v", got)
	}
}

// The harmful variant of the name clash: the user's Secret at the owned name
// happens to carry admin_user and admin_password. Resolve must not adopt it as
// DBaaS's own saved copy (it would then be deleted with the instance).
func TestResolveBYOWithAnOwnedSecretNameDoesNotAdoptTheUsersSecret(t *testing.T) {
	inst := byoInst("pg-orders-credentials", "password")
	users := byoSecret("tenant-a", "pg-orders-credentials", dbaasv1.PasswordSecretType, map[string][]byte{
		"password": []byte("long-enough-password"), "admin_user": []byte("dbadmin"), "admin_password": []byte("also-long-enough"),
	})
	r := resolverWith(t, users)

	result, err := r.Resolve(context.Background(), inst)

	if !errors.Is(err, ErrPasswordSourceInvalid) {
		t.Fatalf("Resolve = (%+v, %v), want ErrPasswordSourceInvalid and no adoption", result.Source, err)
	}
	got, _ := getSecret(t, r, "tenant-a", "pg-orders-credentials")
	if len(got.Annotations) != 0 || len(got.OwnerReferences) != 0 {
		t.Fatalf("the user's Secret was adopted: annotations %v owners %v", got.Annotations, got.OwnerReferences)
	}
}
