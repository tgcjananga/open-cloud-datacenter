#!/usr/bin/env bash
# byo-credentials-e2e.sh — end-to-end test of the master-password feature
# (spec.credentials / "BYO password") against a REAL Harvester cluster.
#
# It exercises, in order: a password full of shell/SQL metacharacters, the
# Secrets DBaaS creates, source-Secret edits and deletion, a lost credentials
# Secret, a missing and an invalid source, the default generated password, a
# repave after the source Secret is gone, the vmPassword policy, and teardown.
#
# ---------------------------------------------------------------------------
# Images this script is written for (the ones on the target cluster)
# ---------------------------------------------------------------------------
#   stream  VirtualMachineImage (namespace "default")   PostgreSQL   role
#   22.04   ubuntu-2204-postgres-v20260515              15 16 17     latest for 22.04
#   24.04   ubuntu-2404-postgres-v20260701              15 16 17 18  latest for 24.04
#   (24.04) ubuntu-2404-postgres-v20260815              18 only      NOT latest for any
#                                                                    stream: the PG-EOL
#                                                                    simulation. NOT used.
# The operator provisions on the latest image of the stream configured as
# databaseDefaults.osVersion (default "22.04"). The stream is platform-wide, so
# this script cannot choose it per instance; it detects it. ENGINE_VERSION
# defaults to 16, which BOTH latest images support.
#
# The repave scenario (B9) needs a different image to move to. With these
# images that means switching the manager's databaseDefaults.osVersion to the
# OTHER stream and redeploying (22.04 -> 24.04), exactly like repave-e2e.sh.
#
# ---------------------------------------------------------------------------
# Requirements
# ---------------------------------------------------------------------------
#   kubectl pointed at the Harvester cluster, with the DBaaS operator running
#   psql on THIS machine, and a network path from it to the VMs' data network
#   an existing NetworkAttachmentDefinition: NETWORK_REF=<namespace>/<name>
#   the images above, imported and Active in the "default" namespace
#
# Usage:
#   NS=<ns> ID=e2e-byo NETWORK_REF=<ns>/<nad> ./byo-credentials-e2e.sh <stage>
#
#   check    read-only: verify the environment, print what will be used
#   stageA   main instance with a BYO password: B1 B2 B7 B10 B3 B4 B5
#   stageB   missing/invalid source, generated password, vmPassword policy:
#            B6 B7 B8 B11
#   stageC   repave of the main instance (B9). Needs the manager already on
#            the other OS stream; see "Between stage B and C" below
#   stageD   teardown checks (B12) and a list of what is left behind
#   cleanup  delete everything this script created (labelled objects only)
#   all      check, A, B, then waits for you to switch the stream, then C, D
#
# Between stage B and C: set databaseDefaults.osVersion to the other stream
# (e.g. add --databaseDefaults.osVersion=24.04 to the manager's args, or the
# config file) and wait for the manager to restart. `all` waits for that on its
# own; with MANUAL_CONTINUE=1 it waits for ENTER instead.
#
# Environment (defaults in brackets):
#   NS, ID              required. ID must start with "e2e-" (a guard: the script
#                       creates and deletes instances with these names)
#   NETWORK_REF         required for A, B. e.g. default/vm-net-100
#   OP_NS               [dbaas-system]   the operator's namespace
#   DB_CLASS            [db.t3.small]    STORAGE_GB [10]   ENGINE_VERSION [16]
#   DB_NAME [e2edb]     MASTER_USER [e2e_admin]
#   OS_STREAM           force the stream instead of detecting it
#   TIMEOUT [1200]      seconds to wait for an instance to become available
#   ASSUME_YES=1        skip the "type the context name" confirmation
#   SKIP_DESTRUCTIVE=1  skip B5 (deletes a live credentials Secret)
#   EXPECT_REJECT_VM_PASSWORD=1|0   override detection of the vmPassword policy
#   MANUAL_CONTINUE=1   in `all`, wait for ENTER instead of polling
#   RESULTS_DIR         [<this directory>/results] where the log and summary go
#
# Safety: every instance and source Secret this script creates carries the
# label dbaas-e2e=byo-credentials. It refuses to start if any of its instance
# names already exist, and every delete or destructive step first checks that
# label. It never touches an object it did not create.
#
# Known behaviour this test works around (not a bug in the script): nothing
# watches the user's source Secret, so editing it does not trigger a reconcile.
# The script nudges one by annotating the DBInstance.
#
# Every run is appended to results/<ns>.<id>.log and results/summary.tsv.

set -uo pipefail

# ---------------------------------------------------------------- constants
LABEL_KEY="dbaas-e2e"
LABEL_VAL="byo-credentials"
SECRET_TYPE="dbaas.opencloud.wso2.com/master-password"
ANN_SRC_SECRET="dbaas.opencloud.wso2.com/password-source-secret"
ANN_SRC_UID="dbaas.opencloud.wso2.com/password-source-uid"
ANN_SRC_RV="dbaas.opencloud.wso2.com/password-source-resource-version"
LABEL_UID="dbaas.opencloud.wso2.com/dbinstance-uid"
ANN_REPAVE="dbaas.opencloud.wso2.com/repave-trigger"
IMAGE_NS="default"

declare -A STREAM_IMAGE=(
  ["22.04"]="ubuntu-2204-postgres-v20260515"
  ["24.04"]="ubuntu-2404-postgres-v20260701"
)
declare -A STREAM_VERSIONS=(
  ["22.04"]="15 16 17"
  ["24.04"]="15 16 17 18"
)
UNUSED_IMAGE="ubuntu-2404-postgres-v20260815"

# Test passwords. Deliberately nasty (quote, double quote, dollar, backslash,
# colon, space, backtick, command substitution) so any quoting mistake in the
# bootstrap path shows up as a failed login. All valid: 8-128 bytes, no newline.
PW_MAIN=$'it\'s"a$HOME\\path:x and spaces'
PW_EDITED='edited-after-acceptance-1'
PW_NOSRC=$'second:pass\\word `ls` $(id) ;'

# ---------------------------------------------------------------- reporting
PASS_COUNT=0; FAIL_COUNT=0; SKIP_COUNT=0; FAILED=0
say()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
pass() { printf '\033[1;32mPASS\033[0m  %s\n' "$*"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*"; FAILED=1; FAIL_COUNT=$((FAIL_COUNT+1)); }
skip() { printf '\033[1;33mSKIP\033[0m  %s\n' "$*"; SKIP_COUNT=$((SKIP_COUNT+1)); }
info() { printf '      %s\n' "$*"; }
die()  { printf '\033[1;31mABORT\033[0m %s\n' "$*"; record_summary "ABORT" 2>/dev/null; exit 1; }

record_summary() { # record_summary <result>
  [ -n "${SUMMARY:-}" ] || return 0
  printf '%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$NS" "$ID" \
    "$STAGE_ARG" "$PASS_COUNT" "$FAIL_COUNT" "$SKIP_COUNT" "$1" >> "$SUMMARY"
}

usage() {
  echo "usage: NS=<ns> ID=e2e-<name> NETWORK_REF=<ns>/<nad> $0 {check|stageA|stageB|stageC|stageD|cleanup|all}" >&2
  echo "       see the header of this file for the full list of environment variables" >&2
  exit 2
}

# ----------------------------------------------------------------- kubectl
dbi() { # dbi <instance> <jsonpath>
  kubectl get dbinstance "$1" -n "$NS" -o jsonpath="$2" 2>/dev/null
}
cond() { # cond <instance> <type> <status|reason|message>
  dbi "$1" "{.status.conditions[?(@.type==\"$2\")].$3}"
}
phase_of() { dbi "$1" '{.status.phase}'; }
uid_of()   { dbi "$1" '{.metadata.uid}'; }
endpoint() { dbi "$1" '{.status.endpoint.address}'; }
eport()    { local p; p=$(dbi "$1" '{.status.endpoint.port}'); echo "${p:-5432}"; }
secret_b64() { # secret_b64 <ns> <name> <key>
  kubectl get secret "$2" -n "$1" -o jsonpath="{.data.$3}" 2>/dev/null
}
secret_val() { secret_b64 "$@" | base64 -d 2>/dev/null; }
secret_exists() { kubectl get secret "$2" -n "$1" >/dev/null 2>&1; }
secret_field() { # secret_field <ns> <name> <jsonpath>
  kubectl get secret "$2" -n "$1" -o jsonpath="$3" 2>/dev/null
}

# nudge makes the controller reconcile the instance. Nothing watches the user's
# source Secret, so an edit to it alone is not noticed until some other event
# triggers a reconcile; a metadata change on the DBInstance does.
nudge() {
  kubectl annotate dbinstance "$1" -n "$NS" "e2e.dbaas.opencloud.wso2.com/nudge=$(date +%s%N)" --overwrite >/dev/null 2>&1
}

# event_total sums how many times a Warning/Normal event with this reason was
# recorded for the instance. Identical events are folded into one object whose
# .count grows, so counting objects would under-report.
event_total() { # event_total <instance> <reason>
  kubectl get events -n "$NS" \
    --field-selector "involvedObject.kind=DBInstance,involvedObject.name=$1,reason=$2" \
    -o jsonpath='{range .items[*]}{.count}{"\n"}{end}' 2>/dev/null |
    awk '{ s += ($1 == "" ? 1 : $1) } END { print s + 0 }'
}

instance_is_ours() { # the label check that guards every destructive step
  local names
  names=$(kubectl get dbinstance -n "$NS" -l "$LABEL_KEY=$LABEL_VAL" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  case " $names " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}
secret_is_ours() { # secret_is_ours <name>
  local names
  names=$(kubectl get secret -n "$NS" -l "$LABEL_KEY=$LABEL_VAL" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
  case " $names " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}
instance_exists() { kubectl get dbinstance "$1" -n "$NS" >/dev/null 2>&1; }

# ------------------------------------------------------------------ waiting
POLL="${POLL:-5}"
LAST_GOT=""

# until_eq polls a getter command until it prints <want>.
until_eq() { # until_eq <timeout-s> <want> <getter...>
  local t="$1" want="$2" start now got
  shift 2
  start=$(date +%s)
  while true; do
    got=$("$@" 2>/dev/null)
    LAST_GOT="$got"
    [ "$got" = "$want" ] && return 0
    now=$(date +%s)
    [ $((now - start)) -ge "$t" ] && return 1
    sleep "$POLL"
  done
}

# stays_eq checks a getter keeps printing <want> for the whole duration.
stays_eq() { # stays_eq <duration-s> <want> <getter...>
  local t="$1" want="$2" start now got
  shift 2
  start=$(date +%s)
  while true; do
    got=$("$@" 2>/dev/null)
    LAST_GOT="$got"
    [ "$got" = "$want" ] || return 1
    now=$(date +%s)
    [ $((now - start)) -ge "$t" ] && return 0
    sleep "$POLL"
  done
}

wait_phase() { # wait_phase <instance> <target> [timeout]
  local id="$1" target="$2" t="${3:-$TIMEOUT}" start now p
  start=$(date +%s)
  while true; do
    p=$(phase_of "$id")
    [ "$p" = "$target" ] && { echo; return 0; }
    now=$(date +%s)
    if [ $((now - start)) -ge "$t" ]; then
      echo; fail "$id: timed out (${t}s) waiting for phase=$target (last: ${p:-<none>})"; return 1
    fi
    printf '\r   waiting: %s phase=%-24s (%ss)' "$id" "${p:-<none>}" "$((now - start))"
    sleep "$POLL"
  done
}

# -------------------------------------------------------------- database
login_ok() { # login_ok <instance> <user> <password> [db]  -> 0 on a working login
  local ep port
  ep=$(endpoint "$1"); port=$(eport "$1")
  [ -n "$ep" ] || return 2
  PGPASSWORD="$3" PGSSLMODE=require PGCONNECT_TIMEOUT=10 \
    psql -X -w -h "$ep" -p "$port" -U "$2" -d "${4:-$DB_NAME}" -tAc 'SELECT 1' 2>/dev/null | grep -qx 1
}
sql_as() { # sql_as <instance> <user> <password> <sql>
  local ep port
  ep=$(endpoint "$1"); port=$(eport "$1")
  PGPASSWORD="$3" PGSSLMODE=require PGCONNECT_TIMEOUT=10 \
    psql -X -w -h "$ep" -p "$port" -U "$2" -d "$DB_NAME" -tAc "$4" 2>&1
}
wait_login() { # wait_login <instance> <user> <password> [timeout]
  local t="${4:-120}" start now
  start=$(date +%s)
  while ! login_ok "$1" "$2" "$3"; do
    now=$(date +%s)
    [ $((now - start)) -ge "$t" ] && return 1
    sleep "$POLL"
  done
}

# -------------------------------------------------------------- manifests
creds_yaml() { # creds_yaml <secret-name> [key]
  printf '  credentials:\n    passwordSource:\n      secretRef:\n        name: "%s"\n        key: "%s"\n' "$1" "${2:-password}"
}
manifest() { # manifest <name> [extra spec yaml, already indented two spaces]
  cat <<EOF
apiVersion: dbaas.opencloud.wso2.com/v1alpha1
kind: DBInstance
metadata:
  name: $1
  namespace: $NS
  labels:
    $LABEL_KEY: $LABEL_VAL
spec:
  dbInstanceClass: $DB_CLASS
  allocatedStorage: $STORAGE_GB
  engineVersion: "$ENGINE_VERSION"
  dbName: $DB_NAME
  masterUsername: $MASTER_USER
  networkRef: $NETWORK_REF
  backupRetentionPeriod: 0
  deletionProtection: false
  running: true
${2:-}
EOF
}
apply_manifest() { # reads a manifest on stdin
  # --validate=false: client-side validation downloads the OpenAPI schema, which
  # fails on some Harvester clusters (kubectl/apiserver skew). The API server
  # still validates everything.
  kubectl apply --validate=false -f - >/dev/null
}

mk_source() { # mk_source <name> <password> — the typed, labelled password Secret
  local f rc
  f="$WORK/pw.$RANDOM$RANDOM"
  ( umask 077; printf '%s' "$2" > "$f" )
  kubectl create secret generic "$1" -n "$NS" --type="$SECRET_TYPE" --from-file=password="$f" >/dev/null &&
    kubectl label secret "$1" -n "$NS" "$LABEL_KEY=$LABEL_VAL" >/dev/null
  rc=$?
  shred -u "$f" 2>/dev/null || rm -f "$f"
  return $rc
}
set_source_password() { # set_source_password <name> <password>
  local b64
  b64=$(printf '%s' "$2" | base64 -w0)
  kubectl patch secret "$1" -n "$NS" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/data/password\",\"value\":\"$b64\"}]" >/dev/null
}

expect_rejected() { # expect_rejected <label> <substring>   (manifest on stdin)
  local out rc
  out=$(kubectl apply --dry-run=server --validate=false -f - 2>&1); rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qi -- "$2"; then
    pass "API rejects: $1"
  else
    fail "API did not reject as expected: $1 (exit $rc): $(printf '%s' "$out" | head -c 300)"
  fi
}
expect_patch_rejected() { # expect_patch_rejected <label> <substring> <instance> <kubectl patch args...>
  local out rc
  out=$(kubectl patch dbinstance "$3" -n "$NS" --dry-run=server "${@:4}" 2>&1); rc=$?
  if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qi -- "$2"; then
    pass "API rejects: $1"
  else
    fail "API did not reject as expected: $1 (exit $rc): $(printf '%s' "$out" | head -c 300)"
  fi
}

# -------------------------------------------------------- stream & images
detect_os_stream() {
  if [ -n "${OS_STREAM:-}" ]; then echo "$OS_STREAM"; return; fi
  local dep s cm
  dep=$(kubectl get deploy -n "$OP_NS" -l control-plane=controller-manager \
    -o jsonpath='{.items[0].spec.template.spec.containers[0].args} {.items[0].spec.template.spec.containers[0].env}' 2>/dev/null)
  s=$(printf '%s' "$dep" | grep -o 'databaseDefaults\.osVersion=[0-9.]*' | head -1 | cut -d= -f2)
  if [ -z "$s" ]; then
    s=$(printf '%s' "$dep" | grep -o 'DBAAS_DATABASE_DEFAULTS__OS_VERSION[^}]*' | grep -o '"value":"[0-9.]*"' | head -1 | grep -o '[0-9][0-9.]*')
  fi
  if [ -z "$s" ]; then
    cm=$(kubectl get cm dbaas-operator-config -n "$OP_NS" -o jsonpath='{.data.config\.json}' 2>/dev/null)
    s=$(printf '%s' "$cm" | grep -o '"osVersion"[[:space:]]*:[[:space:]]*"[0-9.]*"' | head -1 | grep -o '[0-9][0-9.]*')
  fi
  echo "${s:-22.04}"
}
other_stream() { if [ "$1" = "22.04" ]; then echo "24.04"; else echo "22.04"; fi; }
stream_of_image() { # stream_of_image <image-name>
  local s
  for s in "${!STREAM_IMAGE[@]}"; do
    [ "${STREAM_IMAGE[$s]}" = "$1" ] && { echo "$s"; return 0; }
  done
  return 1
}
# image_present matches by object name OR display name, like the operator's
# ResolveVMImage. Images uploaded through the Harvester UI get a generated object
# name (image-c8sqv) and keep the catalog name as the display name.
image_present() {
  kubectl get virtualmachineimage "$1" -n "$IMAGE_NS" >/dev/null 2>&1 && return 0
  kubectl get virtualmachineimage -n "$IMAGE_NS" \
    -o jsonpath='{range .items[*]}{.spec.displayName}{"\n"}{end}' 2>/dev/null | grep -qxF -- "$1"
}
rejecting_vm_password() { # is the manager running with security.rejectVMPassword on?
  if [ -n "${EXPECT_REJECT_VM_PASSWORD:-}" ]; then [ "$EXPECT_REJECT_VM_PASSWORD" = "1" ]; return; fi
  local dep cm
  dep=$(kubectl get deploy -n "$OP_NS" -l control-plane=controller-manager \
    -o jsonpath='{.items[0].spec.template.spec.containers[0].args} {.items[0].spec.template.spec.containers[0].env}' 2>/dev/null)
  printf '%s' "$dep" | grep -q 'security\.rejectVMPassword=true' && return 0
  printf '%s' "$dep" | grep -q 'DBAAS_SECURITY__REJECT_VM_PASSWORD[^}]*"value":"true"' && return 0
  cm=$(kubectl get cm dbaas-operator-config -n "$OP_NS" -o jsonpath='{.data.config\.json}' 2>/dev/null)
  printf '%s' "$cm" | grep -q '"rejectVMPassword"[[:space:]]*:[[:space:]]*true'
}

# ------------------------------------------------------------------- state
save_state() { printf '%s=%q\n' "$1" "$2" >> "$STATE"; }
load_state() { [ -f "$STATE" ] && . "$STATE"; }

# =========================================================================
# stage: check
# =========================================================================
stage_check() {
  say "environment"
  command -v kubectl >/dev/null && pass "kubectl found" || fail "kubectl not found"
  command -v psql >/dev/null && pass "psql found" || fail "psql not found (needed to log in to the databases)"
  info "kubectl context: $(kubectl config current-context 2>/dev/null || echo '<none>')"
  kubectl get ns "$NS" >/dev/null 2>&1 && pass "namespace $NS exists" || fail "namespace $NS does not exist"
  kubectl get crd dbinstances.dbaas.opencloud.wso2.com >/dev/null 2>&1 &&
    pass "DBInstance CRD installed" || fail "DBInstance CRD not installed"

  say "operator"
  local dep ready img
  dep=$(kubectl get deploy -n "$OP_NS" -l control-plane=controller-manager -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -n "$dep" ]; then
    ready=$(kubectl get deploy "$dep" -n "$OP_NS" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
    img=$(kubectl get deploy "$dep" -n "$OP_NS" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)
    [ "${ready:-0}" -ge 1 ] && pass "manager $dep is ready ($img)" || fail "manager $dep has no ready replica"
  else
    fail "no manager Deployment with label control-plane=controller-manager in $OP_NS (set OP_NS?)"
  fi
  CUR_STREAM=$(detect_os_stream)
  info "configured OS stream: $CUR_STREAM (set OS_STREAM to override)"
  if rejecting_vm_password; then info "security.rejectVMPassword: ON (B11 will run)"; else info "security.rejectVMPassword: off (B11 will be skipped)"; fi

  say "images (namespace $IMAGE_NS)"
  local s
  for s in 22.04 24.04; do
    if image_present "${STREAM_IMAGE[$s]}"; then
      pass "${STREAM_IMAGE[$s]} present (stream $s, PostgreSQL ${STREAM_VERSIONS[$s]})"
    elif [ "$s" = "$CUR_STREAM" ]; then
      fail "${STREAM_IMAGE[$s]} is missing but is the image for the configured stream $s"
    else
      info "${STREAM_IMAGE[$s]} not present (only needed as the repave target for stage C)"
    fi
  done
  info "$UNUSED_IMAGE is not used by this script (not the latest for any stream)"
  case " ${STREAM_VERSIONS[$CUR_STREAM]:-} " in *" $ENGINE_VERSION "*) pass "ENGINE_VERSION=$ENGINE_VERSION is supported by the $CUR_STREAM image" ;;
    *) fail "ENGINE_VERSION=$ENGINE_VERSION is not supported by the $CUR_STREAM image (supports: ${STREAM_VERSIONS[$CUR_STREAM]:-?})" ;; esac
  local other; other=$(other_stream "$CUR_STREAM")
  case " ${STREAM_VERSIONS[$other]} " in *" $ENGINE_VERSION "*) ;; *)
    info "WARNING: ENGINE_VERSION=$ENGINE_VERSION is not supported by the $other image, so stage C's repave would be blocked" ;; esac

  say "inputs"
  if [ -z "$NETWORK_REF" ]; then
    fail "NETWORK_REF is not set (e.g. default/vm-net-100). Available:"
    kubectl get network-attachment-definitions -A 2>/dev/null | sed 's/^/      /'
  else
    local nns="${NETWORK_REF%%/*}" nname="${NETWORK_REF##*/}"
    if kubectl get network-attachment-definitions "$nname" -n "$nns" >/dev/null 2>&1; then
      pass "NAD $NETWORK_REF exists"
    else
      fail "NAD $NETWORK_REF not found. NETWORK_REF is <namespace>/<name>; the NADs on this cluster are:"
      kubectl get network-attachment-definitions -A 2>/dev/null | sed 's/^/      /'
    fi
  fi
  case "$DB_CLASS" in db.t3.micro|db.t3.small|db.t3.medium|db.t3.large|db.t3.xlarge) pass "DB_CLASS=$DB_CLASS is a known class" ;;
    *) info "DB_CLASS=$DB_CLASS is not one of the built-in classes (fine if you configured your own)" ;; esac

  say "no leftovers from an earlier run"
  local n clash=0
  for n in "$ID_MAIN" "$ID_NOSRC" "$ID_GEN" "$ID_VMPW"; do
    if instance_exists "$n"; then fail "DBInstance $n already exists in $NS"; clash=1; fi
  done
  [ $clash -eq 0 ] && pass "none of the instance names are in use"
}

# =========================================================================
# stage A: the main BYO instance
# =========================================================================
stage_a() {
  [ -n "$NETWORK_REF" ] || die "NETWORK_REF is required"
  local n
  for n in "$ID_MAIN" "$ID_NOSRC" "$ID_GEN" "$ID_VMPW"; do
    instance_exists "$n" && die "DBInstance $n already exists in $NS — refusing to touch it (use a different ID, or run 'cleanup' if it is from an earlier run of this script)"
  done
  CUR_STREAM=$(detect_os_stream)
  image_present "${STREAM_IMAGE[$CUR_STREAM]:-none}" || die "image ${STREAM_IMAGE[$CUR_STREAM]:-<unknown for stream $CUR_STREAM>} is not present in $IMAGE_NS"

  say "B7a: the API rejects invalid credentials at create time (server-side dry run)"
  manifest "${ID}-apicheck" "$(creds_yaml "" password)"            | expect_rejected "empty Secret name" "secretRef.name"
  manifest "${ID}-apicheck" "$(creds_yaml "Orders-DB" password)"   | expect_rejected "Secret name with uppercase" "secretRef.name"
  manifest "${ID}-apicheck" "$(creds_yaml "$SRC_MAIN" "pass word")" | expect_rejected "key with a space" "secretRef.key"
  manifest "${ID}-apicheck" "$(creds_yaml "$SRC_MAIN")
  masterUserPasswordRef: {name: legacy, key: password}" | expect_rejected "credentials together with masterUserPasswordRef" "cannot be combined"
  local dropped
  dropped=$(manifest "${ID}-apicheck" "$(creds_yaml "$SRC_MAIN")      consumePolicy: Retain" |
    kubectl apply --dry-run=server --validate=false -f - -o jsonpath='{.spec.credentials.passwordSource}' 2>&1)
  if printf '%s' "$dropped" | grep -q secretRef && ! printf '%s' "$dropped" | grep -q consumePolicy; then
    pass "unknown field consumePolicy is dropped silently, not stored"
  else
    fail "consumePolicy handling unexpected: $dropped"
  fi

  say "B1: create with a password full of shell and SQL metacharacters"
  mk_source "$SRC_MAIN" "$PW_MAIN" || die "could not create the source Secret $SRC_MAIN"
  manifest "$ID_MAIN" "$(creds_yaml "$SRC_MAIN")" | apply_manifest || die "could not apply the DBInstance"
  wait_phase "$ID_MAIN" available || die "$ID_MAIN never became available"
  local uid; uid=$(uid_of "$ID_MAIN")
  save_state MAIN_UID "$uid"

  if wait_login "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" 180; then
    pass "the exact password logs in over SSL (all special characters survived)"
  else
    fail "login with the exact password failed — check the quoting path (cloud-init / bootstrap.sh)"
  fi
  if login_ok "$ID_MAIN" "$MASTER_USER" "${PW_MAIN}x"; then fail "a near-miss password was accepted"
  else pass "a near-miss password is refused"; fi
  [ "$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_password)" = "$PW_MAIN" ] &&
    pass "pg-${ID_MAIN}-credentials holds the accepted password" || fail "the saved copy does not match the password"
  [ "$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_user)" = "$MASTER_USER" ] &&
    pass "saved admin_user is $MASTER_USER" || fail "saved admin_user is wrong"
  local src_uid; src_uid=$(secret_field "$NS" "$SRC_MAIN" '{.metadata.uid}')
  [ "$(dbi "$ID_MAIN" '{.status.credentials.source}')" = "UserProvidedSecret" ] &&
    pass "status.credentials.source = UserProvidedSecret" || fail "status.credentials.source = $(dbi "$ID_MAIN" '{.status.credentials.source}')"
  [ "$(dbi "$ID_MAIN" '{.status.credentials.sourceSecretName}')" = "$SRC_MAIN" ] &&
    pass "status names the source Secret" || fail "status.credentials.sourceSecretName is wrong"
  [ "$(dbi "$ID_MAIN" '{.status.credentials.sourceUID}')" = "$src_uid" ] &&
    pass "status.credentials.sourceUID matches the Secret's UID" || fail "sourceUID does not match"
  [ "$(dbi "$ID_MAIN" '{.status.credentials.sourceChanged}')" != "true" ] &&
    pass "sourceChanged starts false" || fail "sourceChanged is already true"
  [ "$(cond "$ID_MAIN" CredentialsReady reason)" = "CredentialsProvisioned" ] &&
    pass "CredentialsReady = CredentialsProvisioned" || fail "CredentialsReady reason = $(cond "$ID_MAIN" CredentialsReady reason)"

  say "B2: the five Secrets DBaaS creates, and the user's own Secret untouched"
  local owned; owned=$(kubectl get secret -n "$NS" -o jsonpath="{range .items[?(@.metadata.ownerReferences[0].name==\"$ID_MAIN\")]}{.metadata.name}{\"\\n\"}{end}" 2>/dev/null | sort | tr '\n' ' ')
  [ "$owned" = "pg-${ID_MAIN}-cloudinit pg-${ID_MAIN}-connect pg-${ID_MAIN}-credentials " ] &&
    pass "tenant namespace: exactly pg-<id>-credentials, -connect, -cloudinit are owned by the instance" ||
    fail "owned tenant Secrets = [$owned]"
  local opn; opn=$(kubectl get secret -n "$OP_NS" -l "$LABEL_UID=$uid" -o name 2>/dev/null | wc -l | tr -d ' ')
  [ "$opn" = "2" ] && pass "operator namespace: two Secrets (internal credentials, TLS) carry the instance UID label" ||
    fail "operator namespace has $opn labelled Secrets, want 2"
  secret_exists "$OP_NS" "dbi-${uid}-internal" && secret_exists "$OP_NS" "dbi-${uid}-tls" &&
    pass "dbi-<uid>-internal and dbi-<uid>-tls exist" || fail "dbi-<uid>-internal / -tls missing"
  [ -z "$(secret_field "$NS" "$SRC_MAIN" '{.metadata.ownerReferences}')" ] &&
    pass "the user's Secret has no owner reference" || fail "the user's Secret gained an owner reference"
  [ "$(secret_field "$NS" "$SRC_MAIN" '{.metadata.resourceVersion}')" = "$(dbi "$ID_MAIN" '{.status.credentials.sourceResourceVersion}')" ] &&
    pass "the user's Secret is unchanged since it was accepted" || fail "the user's Secret changed during provisioning"

  say "B10: the cloud-init Secret is blanked once the database is ready"
  if [ "$(cond "$ID_MAIN" MonitoringReady status)" != "True" ]; then
    skip "MonitoringReady is not True (is the Prometheus ServiceMonitor CRD installed?): cleanup runs after monitoring, so it is not expected yet"
  else
    if until_eq 180 yes cloudinit_redacted "$ID_MAIN"; then pass "cloud-init userdata is the redacted placeholder"
    else fail "cloud-init userdata was never redacted"; fi
  fi
  if kubectl get secret "pg-${ID_MAIN}-cloudinit" -n "$NS" -o jsonpath='{.data.userdata}' 2>/dev/null | base64 -d 2>/dev/null | grep -q 'MASTER_PASSWORD'; then
    info "note: the cloud-init Secret still contains MASTER_PASSWORD (expected only until it is redacted)"
  fi

  say "B7b: the API rejects changing credentials after creation"
  expect_patch_rejected "changing the secretRef" "credentials is immutable" "$ID_MAIN" --type merge \
    -p '{"spec":{"credentials":{"passwordSource":{"secretRef":{"name":"another-secret"}}}}}'
  expect_patch_rejected "removing credentials" "credentials is immutable" "$ID_MAIN" --type json \
    -p '[{"op":"remove","path":"/spec/credentials"}]'

  say "B3: editing the source Secret after the database is available"
  local rv_before events
  rv_before=$(dbi "$ID_MAIN" '{.status.credentials.sourceResourceVersion}')
  set_source_password "$SRC_MAIN" "$PW_EDITED" || fail "could not edit the source Secret"
  info "nothing watches the user's Secret, so nudging a reconcile"
  nudge "$ID_MAIN"
  if until_eq 120 true dbi "$ID_MAIN" '{.status.credentials.sourceChanged}'; then pass "status.credentials.sourceChanged = true"
  else fail "sourceChanged never became true (last: ${LAST_GOT:-<empty>})"; fi
  if until_eq 90 1 event_total "$ID_MAIN" PasswordSourceChanged; then pass "exactly one PasswordSourceChanged Warning event"
  else fail "PasswordSourceChanged events = ${LAST_GOT:-0}, want 1"; fi
  nudge "$ID_MAIN"; sleep 15; nudge "$ID_MAIN"; sleep 15
  [ "$(event_total "$ID_MAIN" PasswordSourceChanged)" = "1" ] &&
    pass "still one event after further reconciles (not repeated)" || fail "the event was repeated: $(event_total "$ID_MAIN" PasswordSourceChanged)"
  [ "$(phase_of "$ID_MAIN")" = "available" ] && pass "phase is still available" || fail "phase = $(phase_of "$ID_MAIN")"
  login_ok "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" && pass "the ORIGINAL password still works" || fail "the original password no longer works"
  login_ok "$ID_MAIN" "$MASTER_USER" "$PW_EDITED" && fail "the EDITED password was applied to the database" ||
    pass "the edited password is not accepted: editing the source does not change the database"
  [ "$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_password)" = "$PW_MAIN" ] &&
    pass "the saved copy still holds the original password" || fail "the saved copy changed"
  [ "$(dbi "$ID_MAIN" '{.status.credentials.sourceResourceVersion}')" = "$rv_before" ] &&
    pass "the recorded source identity is the one from acceptance" || fail "the recorded source identity changed"

  say "B4: deleting the source Secret"
  events=$(event_total "$ID_MAIN" PasswordSourceChanged)
  kubectl delete secret "$SRC_MAIN" -n "$NS" >/dev/null || fail "could not delete the source Secret"
  nudge "$ID_MAIN"; sleep 20
  [ "$(phase_of "$ID_MAIN")" = "available" ] && pass "phase is still available" || fail "phase = $(phase_of "$ID_MAIN")"
  [ "$(cond "$ID_MAIN" CredentialsReady reason)" = "CredentialsProvisioned" ] &&
    pass "CredentialsReady is unaffected" || fail "CredentialsReady reason = $(cond "$ID_MAIN" CredentialsReady reason)"
  [ "$(event_total "$ID_MAIN" PasswordSourceChanged)" = "$events" ] &&
    pass "deleting the source produced no new event" || fail "a new event appeared after deleting the source"
  login_ok "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" && pass "the database is still reachable with the original password" || fail "login failed after the source was deleted"
  secret_exists "$NS" "pg-${ID_MAIN}-credentials" && pass "the saved copy is still there" || fail "the saved copy disappeared"

  if [ -n "${SKIP_DESTRUCTIVE:-}" ]; then
    skip "B5 skipped (SKIP_DESTRUCTIVE is set)"
  else
    say "B5: losing the saved credentials Secret"
    instance_is_ours "$ID_MAIN" || die "refusing B5: $ID_MAIN does not carry the $LABEL_KEY=$LABEL_VAL label"
    local saved_user saved_pw a_name a_uid a_rv f1 f2
    saved_user=$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_user)
    saved_pw=$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_password)
    a_name=$(secret_field "$NS" "pg-${ID_MAIN}-credentials" "{.metadata.annotations.dbaas\\.opencloud\\.wso2\\.com/password-source-secret}")
    a_uid=$(secret_field "$NS" "pg-${ID_MAIN}-credentials" "{.metadata.annotations.dbaas\\.opencloud\\.wso2\\.com/password-source-uid}")
    a_rv=$(secret_field "$NS" "pg-${ID_MAIN}-credentials" "{.metadata.annotations.dbaas\\.opencloud\\.wso2\\.com/password-source-resource-version}")
    [ -n "$saved_pw" ] || die "could not read the saved copy before deleting it"
    kubectl delete secret "pg-${ID_MAIN}-credentials" -n "$NS" >/dev/null || fail "could not delete the credentials Secret"
    if until_eq 90 CredentialsLost cond "$ID_MAIN" CredentialsReady reason; then pass "CredentialsReady = CredentialsLost"
    else fail "CredentialsLost never appeared (reason: ${LAST_GOT:-<none>})"; fi
    info "waiting over one 30s poll to prove nothing is regenerated"
    sleep 45
    secret_exists "$NS" "pg-${ID_MAIN}-credentials" && fail "a replacement credentials Secret was GENERATED" ||
      pass "no replacement Secret was generated"
    [ "$(phase_of "$ID_MAIN")" = "available" ] && pass "the database stays available" || fail "phase = $(phase_of "$ID_MAIN")"
    [ "$(cond "$ID_MAIN" InterventionRequired status)" = "True" ] && pass "InterventionRequired = True" || fail "InterventionRequired is not True"
    login_ok "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" && pass "the original password still works" || fail "login failed while the Secret was lost"
    [ "$(event_total "$ID_MAIN" CredentialsLost)" = "1" ] && pass "exactly one CredentialsLost Warning event across several polls" ||
      fail "CredentialsLost events = $(event_total "$ID_MAIN" CredentialsLost)"

    info "restoring the Secret by hand, as the runbook says"
    f1="$WORK/u.$RANDOM"; f2="$WORK/p.$RANDOM"
    ( umask 077; printf '%s' "$saved_user" > "$f1"; printf '%s' "$saved_pw" > "$f2" )
    kubectl create secret generic "pg-${ID_MAIN}-credentials" -n "$NS" \
      --from-file=admin_user="$f1" --from-file=admin_password="$f2" >/dev/null || fail "could not recreate the credentials Secret"
    shred -u "$f1" "$f2" 2>/dev/null || rm -f "$f1" "$f2"
    kubectl label secret "pg-${ID_MAIN}-credentials" -n "$NS" "dbaas.opencloud.wso2.com/instance=$ID_MAIN" >/dev/null 2>&1
    if [ -n "$a_name" ]; then
      kubectl annotate secret "pg-${ID_MAIN}-credentials" -n "$NS" \
        "$ANN_SRC_SECRET=$a_name" "$ANN_SRC_UID=$a_uid" "$ANN_SRC_RV=$a_rv" >/dev/null 2>&1
    fi
    if until_eq 120 CredentialsProvisioned cond "$ID_MAIN" CredentialsReady reason; then pass "recovered: CredentialsReady = CredentialsProvisioned"
    else fail "did not recover after the Secret was restored (reason: ${LAST_GOT:-<none>})"; fi
    until_eq 60 False cond "$ID_MAIN" InterventionRequired status && pass "InterventionRequired cleared" || fail "InterventionRequired still ${LAST_GOT:-set}"
    login_ok "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" && pass "login works after the restore" || fail "login failed after the restore"
  fi

  record_summary "$([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
}

cloudinit_redacted() { # prints yes/no
  local ud
  ud=$(kubectl get secret "pg-$1-cloudinit" -n "$NS" -o jsonpath='{.data.userdata}' 2>/dev/null | base64 -d 2>/dev/null | tr -d '\n')
  if [ "$ud" = '#cloud-config{}' ]; then echo yes; else echo no; fi
}

# =========================================================================
# stage B: missing source, generated password, vmPassword policy
# =========================================================================
stage_b() {
  [ -n "$NETWORK_REF" ] || die "NETWORK_REF is required"
  instance_exists "$ID_MAIN" && ! instance_is_ours "$ID_MAIN" && die "$ID_MAIN exists but was not created by this script"
  local n
  for n in "$ID_NOSRC" "$ID_GEN"; do
    instance_exists "$n" && die "DBInstance $n already exists in $NS — refusing to touch it"
  done

  say "B6a: a BYO instance whose source Secret does not exist yet"
  manifest "$ID_NOSRC" "$(creds_yaml "$SRC_NOSRC")" | apply_manifest || die "could not apply $ID_NOSRC"
  info "also starting the generated-password instance now, so both provision in parallel"
  manifest "$ID_GEN" "" | apply_manifest || die "could not apply $ID_GEN"

  if until_eq 180 PasswordSourceNotFound cond "$ID_NOSRC" CredentialsReady reason; then pass "CredentialsReady = PasswordSourceNotFound"
  else fail "PasswordSourceNotFound never appeared (reason: ${LAST_GOT:-<none>})"; fi
  [ "$(cond "$ID_NOSRC" CredentialsReady message | grep -c "$SRC_NOSRC")" -ge 1 ] &&
    pass "the message names the missing Secret" || fail "the message does not name the missing Secret"
  sleep 40
  kubectl get vm "pg-${ID_NOSRC}" -n "$NS" >/dev/null 2>&1 && fail "a VM was created while the source was missing" || pass "no VM was created"
  secret_exists "$NS" "pg-${ID_NOSRC}-credentials" && fail "a credentials Secret was created while the source was missing" ||
    pass "no credentials Secret was created"
  local nuid; nuid=$(uid_of "$ID_NOSRC")
  [ "$(kubectl get secret -n "$OP_NS" -l "$LABEL_UID=$nuid" -o name 2>/dev/null | wc -l | tr -d ' ')" = "0" ] &&
    pass "no internal or TLS Secrets were created" || fail "operator-namespace Secrets were created for an instance with no password"

  say "B6b: the user creates the Secret, and provisioning continues"
  mk_source "$SRC_NOSRC" "$PW_NOSRC" || die "could not create $SRC_NOSRC"
  wait_phase "$ID_NOSRC" available || die "$ID_NOSRC never became available after its source was created"
  if wait_login "$ID_NOSRC" "$MASTER_USER" "$PW_NOSRC" 180; then pass "the second BYO password (different special characters) logs in"
  else fail "login with the second BYO password failed"; fi

  say "B8: no credentials block = a generated password, as before"
  wait_phase "$ID_GEN" available || die "$ID_GEN never became available"
  local gpw; gpw=$(secret_val "$NS" "pg-${ID_GEN}-credentials" admin_password)
  [ "${#gpw}" = "32" ] && pass "the generated password has 32 characters" || fail "generated password length = ${#gpw}"
  wait_login "$ID_GEN" "$MASTER_USER" "$gpw" 180 && pass "the generated password logs in" || fail "the generated password does not log in"
  [ "$(dbi "$ID_GEN" '{.status.credentials.source}')" = "Generated" ] && pass "status.credentials.source = Generated" ||
    fail "source = $(dbi "$ID_GEN" '{.status.credentials.source}')"
  [ -z "$(dbi "$ID_GEN" '{.status.credentials.sourceSecretName}')" ] && pass "no source Secret is recorded" || fail "a source Secret is recorded"
  secret_field "$NS" "pg-${ID_GEN}-credentials" '{.metadata.annotations}' | grep -q 'password-source' &&
    fail "the generated credentials Secret carries source annotations" || pass "no source annotations on the generated Secret"
  local gowned; gowned=$(kubectl get secret -n "$NS" -o jsonpath="{range .items[?(@.metadata.ownerReferences[0].name==\"$ID_GEN\")]}{.metadata.name}{\"\\n\"}{end}" 2>/dev/null | wc -l | tr -d ' ')
  [ "$gowned" = "3" ] && pass "the same three tenant Secrets exist as for a BYO instance" || fail "owned tenant Secrets = $gowned, want 3"

  say "B7c: credentials cannot be added to an instance that was created without them"
  expect_patch_rejected "adding credentials later" "credentials is immutable" "$ID_GEN" --type merge \
    -p '{"spec":{"credentials":{"passwordSource":{"secretRef":{"name":"x","key":"password"}}}}}'

  say "B11: spec.vmPassword when the operator rejects it"
  if rejecting_vm_password; then
    instance_exists "$ID_VMPW" && die "DBInstance $ID_VMPW already exists"
    manifest "$ID_VMPW" "  vmPassword: console-pw-e2e-test" | apply_manifest || fail "could not apply $ID_VMPW"
    if until_eq 90 VMPasswordNotAllowed cond "$ID_VMPW" Accepted reason; then pass "Accepted = False, reason VMPasswordNotAllowed"
    else fail "Accepted reason = ${LAST_GOT:-<none>}, want VMPasswordNotAllowed"; fi
    [ "$(phase_of "$ID_VMPW")" = "incompatible-parameters" ] && pass "phase = incompatible-parameters" || fail "phase = $(phase_of "$ID_VMPW")"
    kubectl get vm "pg-${ID_VMPW}" -n "$NS" >/dev/null 2>&1 && fail "a VM was created for the rejected instance" || pass "no VM was created"
    secret_exists "$NS" "pg-${ID_VMPW}-credentials" && fail "Secrets were created for the rejected instance" || pass "no Secrets were created"
    cond "$ID_VMPW" Accepted message | grep -q 'console-pw-e2e-test' && fail "the message echoes the password" || pass "the message does not echo the password"
    instance_is_ours "$ID_VMPW" && kubectl delete dbinstance "$ID_VMPW" -n "$NS" --wait=true --timeout=120s >/dev/null 2>&1
  else
    skip "B11: security.rejectVMPassword is off on this manager (set EXPECT_REJECT_VM_PASSWORD=1 to force)"
  fi

  record_summary "$([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
}

# =========================================================================
# stage C: repave after the source Secret is gone
# =========================================================================
stage_c() {
  instance_exists "$ID_MAIN" || die "$ID_MAIN does not exist — run stageA first"
  instance_is_ours "$ID_MAIN" || die "$ID_MAIN was not created by this script"

  local rev stream_now stream_inst target
  rev=$(dbi "$ID_MAIN" '{.status.currentImageRevision}')
  stream_inst=$(stream_of_image "$rev") || die "the instance runs revision '$rev', which this script does not know"
  stream_now=$(detect_os_stream)
  target=$(other_stream "$stream_inst")
  [ "$stream_now" = "$target" ] ||
    die "the manager is configured for stream $stream_now but the instance runs on $stream_inst; set databaseDefaults.osVersion=$target and redeploy first"
  image_present "${STREAM_IMAGE[$target]}" || die "the repave target image ${STREAM_IMAGE[$target]} is not present in $IMAGE_NS"
  info "instance image: $rev (stream $stream_inst)  ->  repave target: ${STREAM_IMAGE[$target]} (stream $target)"
  [ "$(cond "$ID_MAIN" CredentialsReady reason)" = "CredentialsProvisioned" ] || die "CredentialsReady is not healthy; finish stage A (B5 restore) first"
  secret_exists "$NS" "$SRC_MAIN" && info "note: the source Secret still exists; B4 normally deleted it, which is the point of this test"

  say "B9: write a canary row, then repave with the source Secret gone and its password changed"
  login_ok "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" || die "cannot log in with the original password before the repave"
  sql_as "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" "CREATE TABLE IF NOT EXISTS e2e_canary(id int primary key, note text); INSERT INTO e2e_canary VALUES (1,'before repave') ON CONFLICT (id) DO NOTHING;" >/dev/null
  [ "$(sql_as "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" "SELECT note FROM e2e_canary WHERE id=1;")" = "before repave" ] &&
    pass "canary row written" || die "could not write the canary row"

  local base_os_pvc base_data_pvc base_vmi base_connect_uid base_ca
  base_os_pvc=$(dbi "$ID_MAIN" '{.status.resources.osDiskPVCName}')
  base_data_pvc=$(dbi "$ID_MAIN" '{.status.resources.dataVolumeName}')
  base_vmi=$(kubectl get vmi "$(dbi "$ID_MAIN" '{.status.resources.vmName}')" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null)
  base_connect_uid=$(secret_field "$NS" "pg-${ID_MAIN}-connect" '{.metadata.uid}')
  base_ca=$(secret_b64 "$NS" "pg-${ID_MAIN}-connect" 'ca\.crt')

  if until_eq 300 True kubectl get dbinstance "$ID_MAIN" -n "$NS" -o jsonpath='{.status.conditions[?(@.type=="ImageDrift")].status}'; then
    pass "ImageDrift = True ($(cond "$ID_MAIN" ImageDrift reason))"
  else
    fail "ImageDrift never appeared; is the manager really on stream $target?"; die "cannot repave"
  fi

  kubectl annotate dbinstance "$ID_MAIN" -n "$NS" "$ANN_REPAVE=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" --overwrite >/dev/null || die "could not trigger the repave"
  local start now
  start=$(date +%s)
  while [ "$(phase_of "$ID_MAIN")" = "available" ]; do
    now=$(date +%s); [ $((now - start)) -ge 180 ] && { fail "the repave never started"; die "repave did not start"; }
    sleep 3
  done
  wait_phase "$ID_MAIN" available || die "the repave never completed"

  local new_rev; new_rev=$(dbi "$ID_MAIN" '{.status.currentImageRevision}')
  [ "$new_rev" = "${STREAM_IMAGE[$target]}" ] && pass "the instance now runs $new_rev" || fail "currentImageRevision = $new_rev, want ${STREAM_IMAGE[$target]}"
  [ "$(dbi "$ID_MAIN" '{.status.resources.osDiskPVCName}')" != "$base_os_pvc" ] && pass "the OS disk was swapped" || fail "the OS disk name is unchanged"
  [ "$(dbi "$ID_MAIN" '{.status.resources.dataVolumeName}')" = "$base_data_pvc" ] && pass "the data disk is the same ($base_data_pvc)" || fail "the data disk changed"
  [ "$(kubectl get vmi "$(dbi "$ID_MAIN" '{.status.resources.vmName}')" -n "$NS" -o jsonpath='{.metadata.uid}' 2>/dev/null)" != "$base_vmi" ] &&
    pass "the VM was restarted" || fail "the VMI UID is unchanged"
  [ "$(secret_field "$NS" "pg-${ID_MAIN}-connect" '{.metadata.uid}')" = "$base_connect_uid" ] && pass "the connection Secret is the same object" || fail "the connection Secret was recreated"
  [ "$(secret_b64 "$NS" "pg-${ID_MAIN}-connect" 'ca\.crt')" = "$base_ca" ] && pass "the TLS CA is unchanged" || fail "the TLS CA changed across the repave"

  if wait_login "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" 240; then pass "the ORIGINAL password still works after the repave (the saved copy was used, not the source)"
  else fail "login with the original password failed after the repave"; fi
  login_ok "$ID_MAIN" "$MASTER_USER" "$PW_EDITED" && fail "the edited source password became the database password" ||
    pass "the edited password is still not accepted"
  [ "$(sql_as "$ID_MAIN" "$MASTER_USER" "$PW_MAIN" "SELECT note FROM e2e_canary WHERE id=1;")" = "before repave" ] &&
    pass "the canary row survived the repave" || fail "the canary row is missing after the repave"
  [ "$(secret_val "$NS" "pg-${ID_MAIN}-credentials" admin_password)" = "$PW_MAIN" ] &&
    pass "the saved copy still holds the original password" || fail "the saved copy changed"
  [ "$(dbi "$ID_MAIN" '{.status.credentials.source}')" = "UserProvidedSecret" ] && pass "status.credentials.source is unchanged" ||
    fail "status.credentials.source = $(dbi "$ID_MAIN" '{.status.credentials.source}')"
  [ "$(cond "$ID_MAIN" CredentialsReady status)" = "True" ] && pass "CredentialsReady = True" || fail "CredentialsReady is not True"

  record_summary "$([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
}

# =========================================================================
# stage D: teardown
# =========================================================================
stage_d() {
  say "B12: deleting the instances"
  local n uid src
  for n in "$ID_MAIN" "$ID_NOSRC" "$ID_GEN"; do
    instance_exists "$n" || { info "$n does not exist, skipping"; continue; }
    instance_is_ours "$n" || die "refusing to delete $n: it does not carry the $LABEL_KEY=$LABEL_VAL label"
    uid=$(uid_of "$n")
    src=""
    [ "$n" = "$ID_MAIN" ] && src="$SRC_MAIN"
    [ "$n" = "$ID_NOSRC" ] && src="$SRC_NOSRC"
    local src_rv_before=""
    [ -n "$src" ] && secret_exists "$NS" "$src" && src_rv_before=$(secret_field "$NS" "$src" '{.metadata.resourceVersion}')

    kubectl delete dbinstance "$n" -n "$NS" --wait=true --timeout=300s >/dev/null 2>&1 || fail "deleting $n did not finish in 300s"
    instance_exists "$n" && fail "$n still exists after the delete" || pass "$n is gone"
    kubectl get vm "pg-${n}" -n "$NS" >/dev/null 2>&1 && fail "VM pg-$n still exists" || pass "$n: the VM is gone"
    local s gone=1
    for s in "pg-${n}-credentials" "pg-${n}-connect" "pg-${n}-cloudinit"; do
      secret_exists "$NS" "$s" && { fail "$s still exists"; gone=0; }
    done
    [ $gone -eq 1 ] && pass "$n: the three tenant Secrets are gone"
    if [ -n "$uid" ]; then
      secret_exists "$OP_NS" "dbi-${uid}-internal" && fail "dbi-${uid}-internal still exists" || pass "$n: dbi-<uid>-internal is gone"
      secret_exists "$OP_NS" "dbi-${uid}-tls" && fail "dbi-${uid}-tls still exists" || pass "$n: dbi-<uid>-tls is gone"
      [ "$(kubectl get secret -n "$OP_NS" -l "$LABEL_UID=$uid" -o name 2>/dev/null | wc -l | tr -d ' ')" = "0" ] &&
        pass "$n: nothing left in $OP_NS carrying its UID label" || fail "Secrets carrying the UID label remain in $OP_NS"
    fi
    if [ -n "$src_rv_before" ]; then
      if secret_exists "$NS" "$src" && [ "$(secret_field "$NS" "$src" '{.metadata.resourceVersion}')" = "$src_rv_before" ]; then
        pass "$n: the user's Secret $src was NOT deleted or modified by the teardown"
      else
        fail "$n: the user's Secret $src was deleted or modified by the teardown"
      fi
    elif [ -n "$src" ]; then
      info "$n: its source Secret $src was already deleted earlier, so there is nothing to check"
    fi
  done

  say "left behind (information, not asserted)"
  info "PVCs in $NS mentioning these instances (whether Harvester removes them with the VM is not asserted):"
  kubectl get pvc -n "$NS" 2>/dev/null | grep -E "pg-(${ID_MAIN}|${ID_NOSRC}|${ID_GEN})" | sed 's/^/        /' || info "  none"
  info "user Secrets still present (yours to delete):"
  kubectl get secret -n "$NS" -l "$LABEL_KEY=$LABEL_VAL" -o name 2>/dev/null | sed 's/^/        /'

  record_summary "$([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
}

# =========================================================================
# cleanup
# =========================================================================
stage_cleanup() {
  say "cleanup: deleting what this script created (labelled objects only)"
  local n
  for n in "$ID_VMPW" "$ID_GEN" "$ID_NOSRC" "$ID_MAIN"; do
    instance_exists "$n" || continue
    if instance_is_ours "$n"; then
      kubectl delete dbinstance "$n" -n "$NS" --wait=true --timeout=300s >/dev/null 2>&1 && info "deleted DBInstance $n" || info "could not finish deleting $n"
    else
      info "SKIPPED $n: it is not labelled $LABEL_KEY=$LABEL_VAL"
    fi
  done
  for n in "$SRC_MAIN" "$SRC_NOSRC"; do
    secret_exists "$NS" "$n" || continue
    if secret_is_ours "$n"; then kubectl delete secret "$n" -n "$NS" >/dev/null 2>&1 && info "deleted Secret $n"
    else info "SKIPPED Secret $n: not labelled $LABEL_KEY=$LABEL_VAL"; fi
  done
  rm -f "$STATE"
  pass "cleanup done"
}

# =========================================================================
# all
# =========================================================================
wait_for_stream_switch() { # wait_for_stream_switch <target>
  local target="$1" start now
  echo
  echo "   >>> Switch the manager to OS stream $target now: set databaseDefaults.osVersion=$target"
  echo "   >>> (e.g. add --databaseDefaults.osVersion=$target to manager.args) and let it restart."
  if [ -n "${MANUAL_CONTINUE:-}" ]; then
    read -r -p "   Press ENTER once the manager is running on $target: " _ignored
    return 0
  fi
  start=$(date +%s)
  while [ "$(detect_os_stream)" != "$target" ]; do
    now=$(date +%s)
    [ $((now - start)) -ge 1800 ] && return 1
    printf '\r   waiting for the manager to report stream %s (now: %s) ...  ' "$target" "$(detect_os_stream)"
    sleep 10
  done
  echo
  kubectl rollout status deploy -n "$OP_NS" -l control-plane=controller-manager --timeout=300s >/dev/null 2>&1
  sleep 20
}

stage_all() {
  stage_check
  [ $FAILED -eq 0 ] || die "the environment check failed; fix it before running the stages"
  stage_a
  stage_b
  local rev inst_stream target
  rev=$(dbi "$ID_MAIN" '{.status.currentImageRevision}')
  inst_stream=$(stream_of_image "$rev") || die "unknown image revision '$rev'"
  target=$(other_stream "$inst_stream")
  wait_for_stream_switch "$target" || die "the manager never moved to stream $target"
  stage_c
  stage_d
}

# =========================================================================
main() {
  STAGE_ARG="${1:-}"
  case "$STAGE_ARG" in check|stageA|stageB|stageC|stageD|cleanup|all) ;; *) usage ;; esac

  NS="${NS:?set NS (the tenant namespace to test in)}"
  ID="${ID:?set ID (a base name starting with e2e-, e.g. e2e-byo)}"
  [[ "$ID" =~ ^e2e-[a-z0-9]([-a-z0-9]{0,18}[a-z0-9])?$ ]] ||
    { echo "ID must start with 'e2e-' and be at most 24 lowercase letters/digits/dashes (it is a safety guard: this script creates and deletes instances with these names)" >&2; exit 2; }

  OP_NS="${OP_NS:-dbaas-system}"
  NETWORK_REF="${NETWORK_REF:-}"
  # Same pattern as the CRD's spec.networkRef.
  if [ -n "$NETWORK_REF" ] && ! [[ "$NETWORK_REF" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?/[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
    echo "NETWORK_REF must be <namespace>/<name> of a NetworkAttachmentDefinition (got '$NETWORK_REF'); list them with: kubectl get network-attachment-definitions -A" >&2
    exit 2
  fi
  DB_CLASS="${DB_CLASS:-db.t3.small}"
  STORAGE_GB="${STORAGE_GB:-10}"
  ENGINE_VERSION="${ENGINE_VERSION:-16}"
  DB_NAME="${DB_NAME:-e2edb}"
  MASTER_USER="${MASTER_USER:-e2e_admin}"
  TIMEOUT="${TIMEOUT:-1200}"

  ID_MAIN="$ID"; ID_NOSRC="${ID}-nosrc"; ID_GEN="${ID}-gen"; ID_VMPW="${ID}-vmpw"
  SRC_MAIN="${ID}-pw"; SRC_NOSRC="${ID}-nosrc-pw"

  WORK=$(mktemp -d)
  trap 'rm -rf "$WORK"' EXIT
  STATE="${TMPDIR:-/tmp}/byo-e2e.${NS}.${ID}.state"

  if [ "$STAGE_ARG" != "check" ]; then
    local ctx; ctx=$(kubectl config current-context 2>/dev/null)
    echo "   kubectl context : ${ctx:-<none>}"
    echo "   namespace       : $NS"
    echo "   instances       : $ID_MAIN, $ID_NOSRC, $ID_GEN, $ID_VMPW   (created and deleted by this script)"
    if [ -z "${ASSUME_YES:-}" ]; then
      if [ -t 0 ]; then
        read -r -p "   Type the context name to continue: " answer
        [ "$answer" = "$ctx" ] || { echo "not confirmed" >&2; exit 1; }
      else
        echo "non-interactive run: set ASSUME_YES=1 to confirm the context above" >&2; exit 1
      fi
    fi
  fi

  local script_dir results
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  results="${RESULTS_DIR:-$script_dir/results}"
  mkdir -p "$results"
  LOG="$results/${NS}.${ID}.log"
  SUMMARY="$results/byo-summary.tsv"
  [ -f "$SUMMARY" ] || printf 'timestamp\tns\tid\tstage\tpass\tfail\tskip\tresult\n' > "$SUMMARY"
  { echo; echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) :: $STAGE_ARG ==="; } >> "$LOG"
  exec > >(tee -a "$LOG") 2>&1

  case "$STAGE_ARG" in
    check)   stage_check ;;
    stageA)  stage_a ;;
    stageB)  stage_b ;;
    stageC)  stage_c ;;
    stageD)  stage_d ;;
    cleanup) stage_cleanup ;;
    all)     stage_all ;;
  esac

  echo
  echo "passed: $PASS_COUNT   failed: $FAIL_COUNT   skipped: $SKIP_COUNT"
  [ "$STAGE_ARG" = "check" ] && record_summary "$([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
  [ $FAILED -eq 0 ]
}

# Run only when executed, not when sourced (lets the helpers be tested).
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
