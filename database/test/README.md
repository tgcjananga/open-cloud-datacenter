# Repave E2E Testing

`repave-e2e.sh` is a stage-based test runner for the baked-image + repave
feature. Unlike `test/e2e/`, this needs a real Harvester cluster with
baked images already published.

## Test matrix

| ID | Scenario | Pass condition |
|---|---|---|
| T1 | Provision on stream's current revision | VM boots on the baked image's StorageClass; PG accepts connections without an `apt-get` in cloud-init logs |
| T2 | Register a new revision, don't trigger repave | `ConditionImageDrift=True`/`Reason=OSUpdateAvailable`, VM/data untouched |
| T3 | Trigger repave | VM restarts once, ~30-90s downtime, `pgdata` PVC name unchanged, connection Secret unchanged, TLS cert unchanged |
| T4 | Data survives repave | row counts / canary table written pre-repave present and correct post-repave |
| T5 | Repave trigger while `Stopped` | `ReasonRepaveNotAvailable`, no VM mutation |
| T6 | Old OS-disk PVC deleted post-swap | `kubectl get pvc` shows no pre-swap name lingering |
| T7 | No-op repave (already on latest) | annotation clears, `Satisfied`, zero VM restarts |
| T8 | `databaseDefaults.osVersion` set to a stream not in `LatestBakedImages` (manager misconfiguration) | preflight Terminal on new instances; existing instances' `repave` step `Satisfied`-no-ops (doesn't crash-loop on a bad config value) |
| T9 | Repave failure mid-swap (kill controller between `SwapVMOSDisk` and `DeletePVC`) | re-running the reconcile completes the swap without manual intervention |
| T10 | Concurrent repave triggers, two instances, same namespace | no OS-disk PVC name collision |
| T11 | `kubectl get dbi` shows the new printcolumns and `kubectl describe dbi <name>` shows full condition detail | `ImageDrift` shows `True`/`<none>` in the default table; `ImageDriftReason` appears only with `-o wide`; `describe` shows the standard condition's status, reason, message, observed generation, and transition time |
| E1 | New revision drops the instance's PG major | `ConditionImageDrift=True`/`Reason=EngineVersionEOL` |
| E2 | Repave triggered while blocked (`Reason=EngineVersionEOL`) | Terminal, `ReasonRepaveBlockedEOL`, no destructive op executed |
| E3 | New instance requesting an EOL'd `engineVersion` | `preflight` Terminal, VM never created |
| E4 | Manual `pg_dump`/`pg_restore` migration off an EOL'd instance | row-count-verified data parity |

## Sample manifest

Save as e.g. `test.yaml`, adjusting `networkRef` to a real
NetworkAttachmentDefinition in your cluster:

```yaml
apiVersion: dbaas.opencloud.wso2.com/v1alpha1
kind: DBInstance
metadata:
  name: repave-e2e-test
  namespace: tenant-acme
spec:
  dbInstanceClass: db.t3.medium
  allocatedStorage: 50
  engineVersion: "16"
  dbName: repavetest
  masterUsername: dbadmin
  manageMasterUserPassword: true
  networkRef: default/vm-network
  backupRetentionPeriod: 0
  deletionProtection: false # stage3 deletes this instance as part of its teardown check
  running: true
```

## Running the stages

1. Deploy the manager on the default OS stream (e.g. `22.04`): `make deploy`
2. Provision the baseline instance:
   `NS=tenant-acme ID=repave-e2e-test YAML=./test.yaml ./repave-e2e.sh stage1`
3. Point `databaseDefaults.osVersion` at the next stream (e.g. `24.04`) and redeploy: `make deploy`
4. Verify drift detection + repave:
   `NS=tenant-acme ID=repave-e2e-test ./repave-e2e.sh stage2`
5. Verify teardown + re-apply doesn't reattach the old disk:
   `NS=tenant-acme ID=repave-e2e-test YAML=./test.yaml ./repave-e2e.sh stage3`
6. Publish a new image revision that keeps the same OS stream but drops
   this instance's `engineVersion`, point `LatestBakedImages` at it
   (`ValidationState: Validated`), and redeploy: `make deploy`
7. Verify the EOL-blocked repave path:
   `NS=tenant-acme ID=repave-e2e-test ./repave-e2e.sh stage4`

Stages 5-7 are optional, each testing an independent edge case — see the
usage comment at the top of `repave-e2e.sh` for their manual preconditions:

- `stage5` — manager misconfigured with an unresolvable `osVersion`
- `stage6` — manager killed mid-swap, verifies recovery
- `stage7` — two instances repaved concurrently, no PVC name collision

Every run tees output to `results/<ns>.<id>.log` and appends a row to
`results/summary.tsv`.

---

# BYO credentials E2E (`byo-credentials-e2e.sh`)

End-to-end test of the master-password feature (`spec.credentials`) on a **real** Harvester cluster. It needs the
operator running, `psql` on the machine running the script, a network path from there to the VMs, and a Multus NAD.

```sh
NS=<ns> ID=e2e-byo NETWORK_REF=<ns>/<nad> ./byo-credentials-e2e.sh check     # read-only: verifies the environment
NS=<ns> ID=e2e-byo NETWORK_REF=<ns>/<nad> ./byo-credentials-e2e.sh all       # check, A, B, (you switch stream), C, D
```

Stages: `check`, `stageA` (main BYO instance), `stageB` (missing source, generated password, vmPassword policy),
`stageC` (repave), `stageD` (teardown), `cleanup`. Run `all` for the whole sequence, or the stages one at a time.

| ID | Scenario | Pass condition |
| --- | --- | --- |
| B1 | Create with a password full of `' " $ \ :`, spaces, backticks | Exact password logs in over SSL; a near-miss is refused; status names the source |
| B2 | Count Secrets | Three tenant Secrets owned by the instance, two `dbi-` Secrets in the operator namespace; the user's Secret untouched |
| B3 | Edit the source Secret | Original password still works, edited one is refused, `sourceChanged=true`, exactly one `PasswordSourceChanged` event |
| B4 | Delete the source Secret | Nothing changes, no new event, database reachable |
| B5 | Delete `pg-<id>-credentials` (skip with `SKIP_DESTRUCTIVE=1`) | `CredentialsLost`, **no** replacement generated, database stays available, one event; restoring it recovers |
| B6 | Create with a missing source | `PasswordSourceNotFound`, no VM, no Secrets; creating the source lets it provision |
| B7 | Invalid or immutable input | The API rejects each case; `consumePolicy` is dropped, not stored |
| B8 | No `credentials` block | Generated 32-character password works; `source=Generated`; same three tenant Secrets |
| B9 | Repave after the source was deleted and edited | Original password works afterwards; canary row survives; data disk and TLS CA unchanged |
| B10 | Cloud-init data | Blanked once available (skipped while monitoring is not ready) |
| B11 | `vmPassword` with `security.rejectVMPassword` on | `Accepted=False/VMPasswordNotAllowed`, nothing created (skipped if the policy is off) |
| B12 | Delete the instances | Five Secrets per instance removed; the user's Secret not deleted; leftover PVCs listed |

**Images.** Written for the three images on the target cluster: `ubuntu-2204-postgres-v20260515` (stream 22.04,
PostgreSQL 15-17), `ubuntu-2404-postgres-v20260701` (stream 24.04, PostgreSQL 15-18) and
`ubuntu-2404-postgres-v20260815` (PostgreSQL 18 only, the EOL simulation: not the latest for any stream, so **not
used**). The operator provisions on the latest image of the stream in `databaseDefaults.osVersion`, which is
platform-wide, so the script detects it (override with `OS_STREAM`). `ENGINE_VERSION` defaults to 16, which both
latest images support. **Stage C (repave)** moves to the *other* stream, so between B and C set
`databaseDefaults.osVersion` to it and redeploy; `all` waits for that.

**Safety.** Every instance and Secret the script creates is labelled `dbaas-e2e=byo-credentials`, and every delete
first checks that label. `ID` must start with `e2e-`. The script prints the kubectl context and asks you to type it
(or set `ASSUME_YES=1`). It refuses to start if one of its instance names already exists.

**Heads-up.** Nothing watches the user's source Secret, so editing it does not trigger a reconcile; the script nudges
one by annotating the `DBInstance`. Logs go to `results/` (set `RESULTS_DIR` to change it).


## Stage summary

| Stage | Cases | What it verifies |
| --- | --- | --- |
| `stageA` | B7a, B1, B2, B10, B7b, B3, B4, B5 | The main BYO instance: invalid input is rejected at create time; a password full of shell and SQL metacharacters works exactly; the expected Secrets exist and the user's Secret is untouched; cloud-init data is blanked once available; credentials are immutable; editing or deleting the source Secret does not change the database; losing the saved credentials Secret is reported, never regenerated, and recoverable by hand |
| `stageB` | B6, B8, B7c, B11 | A missing source Secret reports `PasswordSourceNotFound` and provisions once the Secret exists; no `credentials` block gives a generated password; credentials cannot be added later; `vmPassword` is rejected when `security.rejectVMPassword` is on |
| `stageC` | B9 | A repave to the other OS stream keeps the data disk, TLS CA, connection Secret and password, even when the source Secret was deleted and edited beforehand |
| `stageD` | B12 | Deleting the instances removes every Secret the operator owns, leaves the user's Secret alone, and lists any PVCs left behind |

### Things to know

- **B11 needs the policy on.** It is skipped unless the manager runs with `security.rejectVMPassword=true`. Set it as described in [INSTALL.md](../INSTALL.md#production-hardening-reject-vm-password-login), wait for the manager pod to restart, then run `stageB`.
- **PVCs outlive the instance.** Stage D lists the PVCs that remain after deletion (data and OS disks). The operator does not delete them and deleting the VM does not remove them, so clean them up by hand: `kubectl -n <ns> get pvc | grep '^pg-<id>'`.
- **VM check in stage D.** It looks for the VM right after the DBInstance disappears, so a VM still shutting down can be reported as `still exists`. Re-check with `kubectl -n <ns> get vm`.
- **`consumePolicy` check (stage A).** It currently fails with a YAML parse error: the script appends the field to a line whose trailing newline `$(...)` has stripped. The failure is in the script, not the operator. Fix: put `consumePolicy: Retain` on its own line under `passwordSource`.

### Housekeeping

- Stage D does not delete the user's source Secrets. Delete them yourself, or run `cleanup`.
- A stage A that aborts leaves its source Secret behind, and the next run refuses to start (`already exists`). Delete the Secret or run `cleanup` first.
- A B1 wait stuck at `phase=<none>` means no controller reconciled the instance. Check that the manager pod is `Running` and pulling the intended image before suspecting the test.
