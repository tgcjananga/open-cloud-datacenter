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
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	dbaasv1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
)

const (
	// MinPasswordBytes and MaxPasswordBytes bound a user-provided master
	// password. The upper bound keeps it well inside what every consumer
	// (cloud-init, psql, .pgpass) handles; the lower bound rejects trivially
	// short values.
	MinPasswordBytes = 8
	MaxPasswordBytes = 128
)

// Sentinel errors for a user-provided password source. Callers branch with
// errors.Is: NotFound is retryable (the user may not have created the Secret
// yet); Invalid is permanent until the user fixes the Secret or spec.
var (
	// ErrPasswordSourceNotFound: the referenced Secret does not exist.
	ErrPasswordSourceNotFound = errors.New("password source Secret not found")
	// ErrPasswordSourceInvalid: the Secret exists but cannot be used.
	ErrPasswordSourceInvalid = errors.New("password source is invalid")
	// ErrNoPasswordSource: the DBInstance has no spec.credentials block. A
	// caller bug — check Spec.Credentials before resolving.
	ErrNoPasswordSource = errors.New("DBInstance has no spec.credentials password source")
)

// PasswordSourceError describes why a password source was not usable. Its
// message names the Secret and key and says what is wrong, and never contains
// any part of the password.
type PasswordSourceError struct {
	// Kind is ErrPasswordSourceNotFound or ErrPasswordSourceInvalid.
	Kind      error
	Namespace string
	Name      string
	Key       string
	// Detail is a value-free explanation.
	Detail string
}

func (e *PasswordSourceError) Error() string {
	if e.Key == "" {
		return fmt.Sprintf("password source Secret %s/%s: %s", e.Namespace, e.Name, e.Detail)
	}
	return fmt.Sprintf("password source Secret %s/%s key %q: %s", e.Namespace, e.Name, e.Key, e.Detail)
}

func (e *PasswordSourceError) Unwrap() error { return e.Kind }

// PasswordSourceResult is the accepted user-provided password and the identity
// of the Secret it was read from. The identity is recorded in status so a later
// change to the Secret object can be reported; it is never derived from the
// password.
type PasswordSourceResult struct {
	Password        string
	SecretUID       types.UID
	ResourceVersion string
}

// reservedMasterUsers are role names a user-provided master username may not
// take: they belong to the platform or are refused by PostgreSQL itself. The
// comparison ignores case, so "Postgres" is rejected too — a different role in
// PostgreSQL's eyes, but a confusing one. Names with the "pg_" prefix are
// reserved by PostgreSQL.
var reservedMasterUsers = map[string]struct{}{
	"postgres":          {},
	"postgres_exporter": {}, // monitoring role created by bootstrap
	"replicator":        {}, // reserved for replication (repl_password)
	"repl":              {},
	"public":            {}, // refused by CREATE ROLE
	"none":              {}, // refused by CREATE ROLE
}

// ValidateMasterUsername rejects a master username that would collide with a
// platform-managed or PostgreSQL-reserved role.
func ValidateMasterUsername(user string) error {
	lower := strings.ToLower(user)
	if _, reserved := reservedMasterUsers[lower]; reserved || strings.HasPrefix(lower, "pg_") {
		return fmt.Errorf("master username %q is reserved for the platform or PostgreSQL: %w", user, ErrPasswordSourceInvalid)
	}
	return nil
}

// ValidatePassword checks a user-provided master password. The returned error
// is value-free: it says what rule failed, never what the password contains.
func ValidatePassword(password string) error {
	if password == "" {
		return errors.New("value is empty")
	}
	if !utf8.ValidString(password) {
		return errors.New("value is not valid UTF-8")
	}
	if strings.ContainsRune(password, 0) {
		return errors.New("value contains a NUL byte")
	}
	if strings.ContainsAny(password, "\r\n") {
		// Most often a trailing newline from `echo` or a file saved with one.
		return errors.New("value contains a line break (CR or LF); recreate the Secret without a trailing newline, for example with kubectl create secret --from-literal or printf")
	}
	if n := len(password); n < MinPasswordBytes {
		return fmt.Errorf("value is %d bytes, minimum is %d", n, MinPasswordBytes)
	} else if n > MaxPasswordBytes {
		return fmt.Errorf("value is %d bytes, maximum is %d", n, MaxPasswordBytes)
	}
	return nil
}

// ResolvePasswordSource reads and validates the user-provided master password
// named by spec.credentials.passwordSource.secretRef.
//
// The Secret is looked up in the DBInstance's own namespace only; there is no
// cross-namespace reference. Its type must be dbaasv1.PasswordSecretType — a
// guardrail against mistakes, not isolation (see that constant). It does not
// read, create or change any other object, and it never modifies the source.
//
// Errors: *PasswordSourceError wrapping ErrPasswordSourceNotFound (retry) or
// ErrPasswordSourceInvalid (permanent); any other error is a transient API
// failure and is returned unchanged.
func (r *Resolver) ResolvePasswordSource(ctx context.Context, inst *dbaasv1.DBInstance) (PasswordSourceResult, error) {
	if inst.Spec.Credentials == nil {
		return PasswordSourceResult{}, ErrNoPasswordSource
	}
	ref := inst.Spec.Credentials.PasswordSource.SecretRef

	user := inst.Spec.MasterUsername
	if user == "" {
		user = r.DefaultMasterUser
	}
	if err := ValidateMasterUsername(user); err != nil {
		return PasswordSourceResult{}, err
	}

	fail := func(kind error, detail string) (PasswordSourceResult, error) {
		return PasswordSourceResult{}, &PasswordSourceError{
			Kind: kind, Namespace: inst.Namespace, Name: ref.Name, Key: ref.Key, Detail: detail,
		}
	}

	var sec corev1.Secret
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: inst.Namespace, Name: ref.Name}, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return fail(ErrPasswordSourceNotFound, "Secret does not exist in the DBInstance's namespace")
		}
		return PasswordSourceResult{}, fmt.Errorf("read password source Secret %s/%s: %w", inst.Namespace, ref.Name, err)
	}
	if sec.Type != dbaasv1.PasswordSecretType {
		return fail(ErrPasswordSourceInvalid, fmt.Sprintf("Secret has type %q, want %q", sec.Type, dbaasv1.PasswordSecretType))
	}

	password, ok := secretValue(&sec, ref.Key)
	if !ok {
		return fail(ErrPasswordSourceInvalid, "key is not present in the Secret")
	}
	if err := ValidatePassword(password); err != nil {
		return fail(ErrPasswordSourceInvalid, err.Error())
	}
	return PasswordSourceResult{
		Password:        password,
		SecretUID:       sec.UID,
		ResourceVersion: sec.ResourceVersion,
	}, nil
}

// secretValue reads a key from Data (populated by the apiserver), falling back
// to StringData (set on a freshly built object, e.g. under the fake client),
// and reports whether the key exists at all.
func secretValue(s *corev1.Secret, key string) (string, bool) {
	if v, ok := s.Data[key]; ok {
		return string(v), true
	}
	v, ok := s.StringData[key]
	return v, ok
}
