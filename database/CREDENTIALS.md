# Database passwords: choosing, finding and recovering them

For tenants who create a `DBInstance` and platform admins who look after them. The install steps are in [`INSTALL.md`](./INSTALL.md).

## Two ways to get the master password

| | Generated (default) | Your own password (BYO) |
| --- | --- | --- |
| How | Leave `spec.credentials` out | Set `spec.credentials.passwordSource.secretRef` |
| Who picks it | The operator (32 random characters) | You |
| Where you read it | `pg-<name>-credentials` | Your Secret, or `pg-<name>-credentials` |

```sh
# What the database actually uses, in both cases:
kubectl get secret pg-<name>-credentials -n <ns> -o jsonpath='{.data.admin_user}' | base64 -d; echo
kubectl get secret pg-<name>-credentials -n <ns> -o jsonpath='{.data.admin_password}' | base64 -d; echo
```

### Using your own password

1. Create the Secret in the **same namespace** as the `DBInstance`, with this type:

   ```sh
   kubectl create secret generic orders-db-password -n <ns> \
     --type=dbaas.opencloud.wso2.com/master-password \
     --from-file=password=./password.txt      # printf, not echo: no trailing newline
   ```

2. Reference it. A complete example is [`config/samples/dbaas_v1alpha1_dbinstance_byo_password.yaml`](./config/samples/dbaas_v1alpha1_dbinstance_byo_password.yaml):

   ```yaml
   spec:
     credentials:
       passwordSource:
         secretRef: {name: orders-db-password, key: password}
   ```

3. Wait for `phase: available`, then connect with your password.

**Rules** (a problem shows up on the `CredentialsReady` condition, see below):

- The Secret must have the type above. The type only guards against pointing at the wrong Secret. It is not access control: anyone who can write a Secret can set it. RBAC decides who may reference what.
- The password must be valid UTF-8, **8 to 128 bytes**, with no line break. A trailing newline from `echo` is the usual mistake.
- `masterUsername` may not be `postgres`, `postgres_exporter`, `replicator`, `repl`, `public`, `none` or start with `pg_` (any case).
- The Secret may not be named `pg-<name>-credentials`, `pg-<name>-connect` or `pg-<name>-cloudinit`. DBaaS creates and deletes Secrets with those names.
- `credentials` cannot be added, changed or removed after creation, and cannot be combined with `manageMasterUserPassword: true` or `masterUserPasswordRef`.

## What happens after creation

- **Your Secret is a creation-time input.** The operator reads it once and keeps its own copy in `pg-<name>-credentials`. Retries and repaves use that copy.
- **Editing your Secret later does not change the database password.** The instance reports `status.credentials.sourceChanged: true` and one Warning event, `PasswordSourceChanged`. "Changed" means the Secret object changed (a label edit counts), not necessarily the password.
- **Deleting your Secret later changes nothing** and is not reported. The saved copy is what matters.
- **A password changed inside PostgreSQL** (`ALTER ROLE`) is invisible to DBaaS. Update `admin_password` in `pg-<name>-credentials` to match, so the record stays true.
- **A repave keeps the password.** The data disk keeps its roles, so the new VM does not reset them.

## Which Secrets exist

DBaaS creates five per instance; a BYO tenant also sees their own, so six.

| Secret | Namespace | Holds |
| --- | --- | --- |
| `pg-<name>-credentials` | tenant | `admin_user`, `admin_password` (the saved copy) |
| `pg-<name>-connect` | tenant | host, port, database name, JDBC URL, CA certificate. No password |
| `pg-<name>-cloudinit` | tenant | first-boot data, including passwords. Blanked once the database is ready and monitoring is set up. If monitoring keeps failing, it stays unblanked until monitoring recovers |
| `dbi-<uid>-internal` | `dbaas-system` | replication and exporter passwords |
| `dbi-<uid>-tls` | `dbaas-system` | CA key, server certificate and key |

The two `dbi-` Secrets are not readable by tenants. Platform admins can read them.

## Reading the status

```sh
kubectl get dbinstance <name> -n <ns> -o jsonpath='{.status.credentials}{"\n"}'
kubectl get dbinstance <name> -n <ns> -o jsonpath='{.status.conditions[?(@.type=="CredentialsReady")]}{"\n"}'
```

| `CredentialsReady` | Meaning | What to do |
| --- | --- | --- |
| `True`, `CredentialsProvisioned` | Fine | Nothing |
| `False`, `PasswordSourceNotFound` | Your Secret does not exist yet. Nothing was created | Create it in the instance's namespace. It is noticed within about 30 seconds |
| `False`, `PasswordSourceInvalid` | The Secret exists but cannot be used. The message says why and never contains the password | Fix the type, key, length, line break, username or Secret name per the rules above |
| `False`, `CredentialsLost` | A saved Secret is missing but the database is already running. DBaaS will not generate a replacement because it would not match the running database. `InterventionRequired` is `True` and the database stays `available` | See the runbook below |

## Deleting an instance

**Deleted:** the VM, the monitoring Service, Endpoints and ServiceMonitor, and the five Secrets above (the two `dbi-` ones even if their recorded references were lost).

**Kept:**

- **Your own password Secret.** DBaaS never deletes it. Delete it yourself once the instance is gone: `kubectl delete secret <name> -n <ns>`.
- **The disk volumes.** The operator does not delete the data and OS disk PVCs. Whether Harvester removes them with the VM has not been verified, so check with `kubectl get pvc -n <ns>`.

## Runbook: a password or Secret is lost

| Situation | What to do |
| --- | --- |
| Forgot the password; the instance is fine | Read `pg-<name>-credentials` (command above) |
| Your Secret was edited or deleted | The database is unchanged. The password it uses is in `pg-<name>-credentials` |
| `CredentialsLost`: `pg-<name>-credentials` is missing | If you know the password: recreate it with keys `admin_user` and `admin_password`; the operator continues on its next poll. Otherwise restore it from a backup |
| `CredentialsLost`: `dbi-<uid>-internal` or `-tls` is missing | An admin restores it from a cluster backup. DBaaS will not regenerate it: a new CA or exporter password would not match the running VM. With no backup, recreate the instance and restore the data from a `pg_dump` |
| No copy of the password exists anywhere | The old password cannot be recovered (PostgreSQL keeps only a hash). It can only be **reset inside PostgreSQL**, which needs a shell on the VM |

**Resetting inside PostgreSQL**

- **Development installs** that set `spec.vmPassword` have console and SSH login. On the VM run `sudo -u postgres psql -p <port>`, then `\password <master user>`, which prompts for the new password and keeps it out of shell history. Afterwards update `admin_password` in `pg-<name>-credentials`.
- **Production installs** with `security.rejectVMPassword` on have no console or SSH login through the operator, so **this reset is not possible** until DBaaS has a password-reset feature. That feature is waiting on Harvester 1.9.1 (Kube-OVN) support, which is also why recovering from a lost password is manual today. Keep your password Secret, or a copy of the password, somewhere safe.
