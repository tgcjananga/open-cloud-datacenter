# dbaas

A Kubernetes operator that provisions managed PostgreSQL databases as
KubeVirt VMs on a Harvester HCI cluster. One `DBInstance` custom resource
maps to one VM with persistent storage, SSL-only PostgreSQL, an admin
credentials Secret, and optional Prometheus monitoring.

Tested on **Harvester 1.7.1** (RKE2 v1.34.3) — full end-to-end from
`kubectl apply` to `psql` round-trip in ~3 minutes.

## What it does

- **API**: `DBInstance` in group `dbaas.opencloud.wso2.com/v1alpha1`,
  namespaced, with the standard `kubectl get dbi -A` printer columns.
  `dbName` and `masterUsername` are validated against the PostgreSQL
  identifier rules at apply time (`^[a-zA-Z_][a-zA-Z0-9_$]{0,62}$`), so
  invalid names are rejected up front instead of failing later inside
  cloud-init.
- **Reconciler**: phase-based state machine (`NetworkProvisioned →
  StorageProvisioned → VMCreated → WaitingForCloudInit → DatabaseReady →
  MonitoringDeployed → Available`); idempotent and crash-safe via
  `status.resources`. Readiness is confirmed by dialing PostgreSQL's
  TCP listener directly from the controller process (see *Network
  model*) — no helper Pod.
- **REST gateway**: a thin HTTP layer over the CRD exposing the same six
  operations as `kubectl`; mutations are authenticated by forwarding the
  caller's bearer token to the K8s API server (same authn/RBAC/audit path
  as `kubectl`).
- **Network model**: each VM gets **two** NICs:
  - **data-net** — bridged onto a Multus `NetworkAttachmentDefinition`
    supplied via `spec.networkRef`. This is the tenant-facing address,
    published as `status.endpoint.address`. It uses the VLAN's
    DHCP/IPAM by default, or `spec.staticNetwork` for VLANs without one.
  - **mgmt-net** — on the cluster's default pod network (KubeVirt
    `masquerade`, PostgreSQL port exposed). The controller dials the
    launcher pod's IP here to verify readiness, and the VM gets cluster
    egress through it at first boot (so `apt install` doesn't depend on
    the data VLAN's upstream). Only `data-net` is ever published as the
    endpoint; the pod IP stays internal to the control plane.
- **Access control**: the scaffolded `dbinstance-admin/editor/viewer`
  ClusterRoles carry `rbac.authorization.k8s.io/aggregate-to-*` labels,
  so they fold into the built-in `admin`/`edit`/`view` roles. A user
  granted a Rancher project role (or any binding to those K8s roles)
  can manage `DBInstance`s in their namespace with no per-tenant wiring.
  Authorization is pure Kubernetes RBAC — there is no separate DBaaS
  login.
- **Per-instance TLS**: ephemeral CA + server cert generated for each VM
  and pinned via `status.caCertPem`. `pg_hba.conf` enforces
  `hostssl … scram-sha-256` only. The master role is created with
  `CREATEDB`/`CREATEROLE` but **not** `SUPERUSER`.

## What's NOT in this version

The CRD schema is broader than the implementation. The following spec
fields are reserved for forward compatibility but **the reconciler does
not act on them today**:

| Field | Status |
| --- | --- |
| `engineVersion` | Recorded but ignored; cloud-init installs the OS image's apt-default PostgreSQL (Ubuntu 22.04 → PG 14, Ubuntu 24.04 → PG 16). |
| `manageMasterUserPassword`, `masterUserPasswordRef` | Ignored; the controller always generates a random admin password into the credentials Secret. |
| `s3BackupConfig`, `backupRetentionPeriod`, `preferredBackupWindow` | Values are recorded but no pgBackRest install, schedule, or retention runs. |
| `multiAZ` | No Patroni / HA standby is created. |
| `dbParameterGroupRef` | No `DBParameterGroup` CRD exists in this module. |
| `tags` | Not propagated to child resource labels / annotations / dashboards. |
| `status.conditions`, `status.readReplicas` | Defined for forward compatibility; not written by the reconciler. |
| Per-instance `postgres_exporter` | Service + ServiceMonitor are created, but no exporter is installed inside the VM yet, so the scrape target won't return metrics. |

Each is called out in the field's godoc (`kubectl explain dbi.spec.<field>`).
They will be implemented incrementally; the
schema shape is deliberately stable so users can write manifests today
that work later.

## Install

### Option A — Helm (recommended for public users)

```sh
helm install dbaas oci://ghcr.io/tgcjananga/charts/dbaas-operator \
  --version 0.1.0 \
  --namespace dbaas-system \
  --create-namespace
```

On **Kube-OVN** clusters, pass the logical switch so the controller can reach
VM probes across tenant VPCs. On standard pod-network clusters this flag is
safe to omit — the annotation is silently ignored:

```sh
  --set manager.args="{--leader-elect,--mgmt-logical-switch=ovn-default}"
```

Helm lifecycle commands:

```sh
helm upgrade dbaas oci://ghcr.io/tgcjananga/charts/dbaas-operator --version <new-version>  # upgrade
helm rollback dbaas 1 -n dbaas-system         # roll back to previous revision
helm history dbaas -n dbaas-system            # view release history
helm uninstall dbaas -n dbaas-system          # remove everything
```

### Option B — Kustomize / make (for contributors and Terraform path)

```sh
# From inside the database/ directory, with kubectl + docker buildx available:
make docker-buildx IMG=<registry>/<name>:<tag>
KUBECONFIG=<your-harvester-kubeconfig> make install
KUBECONFIG=<your-harvester-kubeconfig> make deploy IMG=<registry>/<name>:<tag>
```

### Option C — Single-file install

```sh
kubectl apply -f https://github.com/wso2/open-cloud-datacenter/releases/download/operators-v0.1.0/install.yaml
```

---

After installing the operator, create a `DBInstance` to provision a database:

```sh
# Then apply a DBInstance — full YAML and walkthrough in USAGE.md
kubectl get dbi -A -w
```

Expected time from `apply` to `phase=available`: about **3 minutes** on
stock Ubuntu cloud images, ~60 s if you pre-bake PostgreSQL into a
custom image (see `DEPLOYMENT.md`).

## Build / test / develop

```sh
make manifests generate fmt vet build   # regenerate CRD + DeepCopy, build manager
make test                               # envtest-backed unit tests
make docker-buildx IMG=...              # cross-build linux/amd64, push
make install                            # apply CRD using current kubeconfig
make deploy IMG=...                     # apply manager + RBAC
make undeploy && make uninstall         # tear it all down
```

## Updating dist/ after config or API changes

`dist/` is generated output — never edit it directly. Regenerate it whenever
you change `api/v1alpha1/*_types.go` or anything under `config/`:

```sh
# If you changed api/v1alpha1/*_types.go:
make manifests          # regenerate CRD YAML from Go types
make generate           # regenerate zz_generated.deepcopy.go

# Always run these after any config/ or types change:
make build-installer IMG=<registry>/<name>:<tag>  # regenerate dist/install.yaml
kubebuilder edit --plugins=helm/v2-alpha           # regenerate dist/chart/

# Verify the chart still renders correctly:
helm lint dist/chart
helm install dbaas dist/chart --dry-run=client --namespace dbaas-system

# Commit source + generated output together:
git add api/ config/ dist/
git commit -m "feat: <describe your change>"

# For a release — package and push the chart to GHCR:
helm package dist/chart --version <tag>
helm push dbaas-operator-<tag>.tgz oci://ghcr.io/tgcjananga/charts
```

## Part of Open Cloud Datacenter

This component lives in the [WSO2 Open Cloud
Datacenter](https://github.com/wso2/open-cloud-datacenter) initiative,
providing managed database services on Harvester HCI.

## License

Apache-2.0
