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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	dbaasv1alpha1 "github.com/wso2/open-cloud-datacenter/crds/dbaas/api/v1alpha1"
)

// The x-kubernetes-validations transition rules (PR9) are enforced by the API
// server itself, so — unlike the rest of this package's fake-client-backed
// unit tests — these specs run against the real envtest API server
// (k8sClient from suite_test.go); a fake client never evaluates CEL.
var _ = Describe("DBInstance immutable-field CEL rules", func() {
	ctx := context.Background()
	var name string
	counter := 0

	BeforeEach(func() {
		counter++
		name = fmt.Sprintf("cel-immutable-%d", counter)
	})

	createInstance := func() *dbaasv1alpha1.DBInstance {
		inst := &dbaasv1alpha1.DBInstance{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: dbaasv1alpha1.DBInstanceSpec{
				DBInstanceClass:  "db.t3.small",
				AllocatedStorage: 20,
				NetworkRef:       "default/vm-network",
				EngineVersion:    "16",
				VMPassword:       "initial",
				StaticNetwork: &dbaasv1alpha1.NetworkConfig{
					Address:     "192.168.40.50/24",
					Gateway:     "192.168.40.1",
					Nameservers: []string{"1.1.1.1"},
				},
			},
		}
		Expect(k8sClient.Create(ctx, inst)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, inst)
		})
		return inst
	}

	It("rejects changing networkRef after creation", func() {
		inst := createInstance()
		inst.Spec.NetworkRef = "default/other-network"
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("networkRef is immutable after creation"))
	})

	It("rejects changing engineVersion after creation", func() {
		inst := createInstance()
		inst.Spec.EngineVersion = "17"
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("engineVersion is immutable after creation"))
	})

	It("rejects changing vmPassword after creation", func() {
		inst := createInstance()
		inst.Spec.VMPassword = "changed"
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("vmPassword is immutable after creation"))
	})

	It("rejects changing staticNetwork after creation", func() {
		inst := createInstance()
		inst.Spec.StaticNetwork.Address = "192.168.40.99/24"
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("staticNetwork is immutable after creation"))
	})

	bareInstance := func() *dbaasv1alpha1.DBInstance {
		inst := &dbaasv1alpha1.DBInstance{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: dbaasv1alpha1.DBInstanceSpec{
				DBInstanceClass:  "db.t3.small",
				AllocatedStorage: 20,
				NetworkRef:       "default/vm-network",
			},
		}
		Expect(k8sClient.Create(ctx, inst)).To(Succeed())
		DeferCleanup(func() {
			_ = k8sClient.Delete(ctx, inst)
		})
		return inst
	}

	// The CEL rules use plain "self == oldSelf": Kubernetes only evaluates a
	// transition rule once the field already has a value on the old object,
	// so filling in a still-unset optional immutable field is a permitted
	// one-time transition — only a set→different-value edit is rejected
	// (covered by the sibling "rejects changing ..." cases above).
	It("allows setting engineVersion once, after creation, when initially unset", func() {
		inst := bareInstance()
		inst.Spec.EngineVersion = "16"
		Expect(k8sClient.Update(ctx, inst)).To(Succeed())

		var got dbaasv1alpha1.DBInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
		Expect(got.Spec.EngineVersion).To(Equal("16"))
	})

	It("allows setting vmPassword once, after creation, when initially unset", func() {
		inst := bareInstance()
		inst.Spec.VMPassword = "first-set"
		Expect(k8sClient.Update(ctx, inst)).To(Succeed())

		var got dbaasv1alpha1.DBInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
		Expect(got.Spec.VMPassword).To(Equal("first-set"))
	})

	It("allows setting staticNetwork once, after creation, when initially unset", func() {
		inst := bareInstance()
		inst.Spec.StaticNetwork = &dbaasv1alpha1.NetworkConfig{
			Address:     "192.168.40.50/24",
			Gateway:     "192.168.40.1",
			Nameservers: []string{"1.1.1.1"},
		}
		Expect(k8sClient.Update(ctx, inst)).To(Succeed())

		var got dbaasv1alpha1.DBInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
		Expect(got.Spec.StaticNetwork).NotTo(BeNil())
		Expect(got.Spec.StaticNetwork.Address).To(Equal("192.168.40.50/24"))
	})

	It("allows a mutable field to change while the immutable fields stay the same", func() {
		inst := createInstance()
		inst.Spec.AllocatedStorage = 30
		Expect(k8sClient.Update(ctx, inst)).To(Succeed())

		var got dbaasv1alpha1.DBInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
		Expect(got.Spec.AllocatedStorage).To(Equal(30))
	})
})

// spec.credentials (BYO master password) validation. Like the rules above,
// these are enforced by the API server, so they run against envtest.
var _ = Describe("DBInstance spec.credentials validation", func() {
	ctx := context.Background()
	var name string
	counter := 0

	BeforeEach(func() {
		counter++
		name = fmt.Sprintf("cel-credentials-%d", counter)
	})

	instance := func(creds *dbaasv1alpha1.CredentialsSpec) *dbaasv1alpha1.DBInstance {
		return &dbaasv1alpha1.DBInstance{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
			Spec: dbaasv1alpha1.DBInstanceSpec{
				DBInstanceClass:  "db.t3.small",
				AllocatedStorage: 20,
				NetworkRef:       "default/vm-network",
				Credentials:      creds,
			},
		}
	}

	byo := func(secret, key string) *dbaasv1alpha1.CredentialsSpec {
		return &dbaasv1alpha1.CredentialsSpec{
			PasswordSource: dbaasv1alpha1.PasswordSource{
				SecretRef: dbaasv1alpha1.PasswordSecretRef{Name: secret, Key: key},
			},
		}
	}

	create := func(inst *dbaasv1alpha1.DBInstance) *dbaasv1alpha1.DBInstance {
		Expect(k8sClient.Create(ctx, inst)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, inst) })
		return inst
	}

	It("accepts an instance with no credentials block (the default, generated password)", func() {
		inst := create(instance(nil))
		Expect(inst.Spec.Credentials).To(BeNil())
	})

	It("accepts a valid BYO secretRef", func() {
		inst := create(instance(byo("orders-db-password", "password")))

		var got dbaasv1alpha1.DBInstance
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
		Expect(got.Spec.Credentials).NotTo(BeNil())
		Expect(got.Spec.Credentials.PasswordSource.SecretRef.Name).To(Equal("orders-db-password"))
		Expect(got.Spec.Credentials.PasswordSource.SecretRef.Key).To(Equal("password"))
		_ = inst
	})

	DescribeTable("rejects an invalid secretRef at create",
		func(secret, key string) {
			err := k8sClient.Create(ctx, instance(byo(secret, key)))
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got: %v", err)
			DeferCleanup(func() { _ = k8sClient.Delete(ctx, instance(nil)) })
		},
		Entry("empty name", "", "password"),
		Entry("empty key", "orders-db-password", ""),
		Entry("name with uppercase", "Orders-DB", "password"),
		Entry("name with a slash (cross-namespace style)", "other-ns/orders-db-password", "password"),
		Entry("name starting with a dash", "-orders", "password"),
		Entry("key with a space", "orders-db-password", "pass word"),
		Entry("key with a slash", "orders-db-password", "a/b"),
	)

	It("rejects a credentials block with no passwordSource", func() {
		err := k8sClient.Create(ctx, instance(&dbaasv1alpha1.CredentialsSpec{}))
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got: %v", err)
	})

	It("rejects changing the secretRef after creation", func() {
		inst := create(instance(byo("orders-db-password", "password")))
		inst.Spec.Credentials.PasswordSource.SecretRef.Name = "another-secret"
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("credentials is immutable after creation"))
	})

	It("rejects removing credentials after creation", func() {
		inst := create(instance(byo("orders-db-password", "password")))
		inst.Spec.Credentials = nil
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("credentials is immutable after creation"))
	})

	// Unlike engineVersion/vmPassword/staticNetwork above, which may be filled
	// in once after creation, credentials may not: the database already has a
	// password by then, so adding a source would be silently ignored.
	It("rejects adding credentials to an instance created without them", func() {
		inst := create(instance(nil))
		inst.Spec.Credentials = byo("orders-db-password", "password")
		err := k8sClient.Update(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("credentials is immutable after creation"))
	})

	It("still allows mutable fields to change on an instance with credentials", func() {
		inst := create(instance(byo("orders-db-password", "password")))
		inst.Spec.AllocatedStorage = 30
		Expect(k8sClient.Update(ctx, inst)).To(Succeed())
	})

	It("rejects credentials together with the reserved masterUserPasswordRef", func() {
		inst := instance(byo("orders-db-password", "password"))
		inst.Spec.MasterUserPasswordRef = &dbaasv1alpha1.SecretKeyRef{Name: "legacy", Key: "password"}
		err := k8sClient.Create(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got: %v", err)
		Expect(err.Error()).To(ContainSubstring("cannot be combined with the reserved"))
	})

	It("rejects credentials together with manageMasterUserPassword: true", func() {
		inst := instance(byo("orders-db-password", "password"))
		inst.Spec.ManageMasterUserPassword = true
		err := k8sClient.Create(ctx, inst)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got: %v", err)
		Expect(err.Error()).To(ContainSubstring("cannot be combined with the reserved"))
	})

	It("still accepts the legacy fields without a credentials block", func() {
		inst := instance(nil)
		inst.Spec.ManageMasterUserPassword = true
		inst.Spec.MasterUserPasswordRef = &dbaasv1alpha1.SecretKeyRef{Name: "legacy", Key: "password"}
		create(inst)
	})

	// Fields that are not in the schema (consumePolicy, reveal, ...) are
	// pruned by the API server, not rejected. The docs rely on this being safe:
	// a user who asks for DeleteAfterSuccessfulApply simply keeps their Secret.
	It("silently drops unknown fields under passwordSource", func() {
		u := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": dbaasv1alpha1.GroupVersion.String(),
			"kind":       "DBInstance",
			"metadata":   map[string]interface{}{"name": name, "namespace": "default"},
			"spec": map[string]interface{}{
				"dbInstanceClass":  "db.t3.small",
				"allocatedStorage": int64(20),
				"networkRef":       "default/vm-network",
				"credentials": map[string]interface{}{
					"managementPolicy": "SelfManaged",
					"passwordSource": map[string]interface{}{
						"secretRef":     map[string]interface{}{"name": "orders-db-password", "key": "password"},
						"consumePolicy": "DeleteAfterSuccessfulApply",
					},
					"reveal": map[string]interface{}{"ttlSeconds": int64(600)},
				},
			},
		}}
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })

		stored := &unstructured.Unstructured{}
		stored.SetGroupVersionKind(u.GroupVersionKind())
		Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, stored)).To(Succeed())
		creds, found, err := unstructured.NestedMap(stored.Object, "spec", "credentials")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(creds).NotTo(HaveKey("managementPolicy"))
		Expect(creds).NotTo(HaveKey("reveal"))
		src := creds["passwordSource"].(map[string]interface{})
		Expect(src).NotTo(HaveKey("consumePolicy"))
		Expect(src).To(HaveKey("secretRef"))
	})

	Describe("status.credentials", func() {
		It("accepts a known source and rejects an unknown one", func() {
			inst := create(instance(byo("orders-db-password", "password")))

			inst.Status.Credentials = &dbaasv1alpha1.CredentialsStatus{
				Source:                dbaasv1alpha1.CredentialsSourceUserProvidedSecret,
				SourceSecretName:      "orders-db-password",
				SourceUID:             "4c0c3b1e-0000-0000-0000-000000000001",
				SourceResourceVersion: "12345",
			}
			Expect(k8sClient.Status().Update(ctx, inst)).To(Succeed())

			var got dbaasv1alpha1.DBInstance
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: "default"}, &got)).To(Succeed())
			Expect(got.Status.Credentials).NotTo(BeNil())
			Expect(got.Status.Credentials.Source).To(Equal(dbaasv1alpha1.CredentialsSourceUserProvidedSecret))
			Expect(got.Status.Credentials.SourceChanged).To(BeFalse())

			got.Status.Credentials.Source = "Bogus"
			err := k8sClient.Status().Update(ctx, &got)
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "got: %v", err)
		})
	})
})
