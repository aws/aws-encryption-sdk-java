#!/usr/bin/env bash
# ============================================================================
# Integration test — ESDK TestServer bootstrap failure paths (task 11.3)
# ----------------------------------------------------------------------------
# Exercises the FAILURE paths of the bootstrap-then-delegate entry point
# (`make test-server`) in the aws-crypto-tools-java Language_Repository:
#
#   * Requirement 4.9: a missing or unparseable commons-configuration.json
#     halts the run BEFORE any clone (no .commons-clone is created), runs no
#     Tests, and reports an error naming the expected file location.
#   * Requirement 4.10: a clone failure — unreachable URL or nonexistent
#     branch — halts the run, runs no Tests, and reports a failure naming the
#     Commons_Repository URL and the branch that could not be obtained. The
#     post-clone sanity check (clone lacks the orchestrator core) reports the
#     same coordinates.
#   * In EVERY failure case: non-zero exit and zero Tests run (the run never
#     reaches the orchestrator-core delegation step).
#
# All cases are hermetic — no network, no JDK, no AWS:
#   * COMMONS_CONFIGURATION points at scratch fixtures for the parse cases,
#     so the real commons-configuration.json is never touched.
#   * COMMONS_REPO points clone attempts at local file:// fixtures built in a
#     temp dir (the Makefile documents COMMONS_REPO as the test-only URL
#     override for exactly this purpose).
#   * HARNESS_JAVA_HOME is stubbed to a non-empty placeholder: every case
#     halts before the delegation step, so no JVM is ever started, and the
#     stub keeps the run independent of local JDK resolution.
#   * CLONE_DIR points into the scratch dir, so the repo's own .commons-clone
#     is never created or removed.
#
# Usage:  bash tests/clone_setup_failure_it.sh    (or `make -C .. it`)
# Exit code is non-zero if any assertion fails.
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$HERE/.." && pwd)"          # aws-crypto-tools-java/esdk/test-server
MAKE=(make -C "$TS_DIR")

# Non-empty stub: satisfies check-harness-java without resolving a real JDK.
# Safe because every case below halts before the delegation step uses it.
JAVA_STUB="/nonexistent-hermetic-it-jdk-stub"

pass=0
fail=0
ok()  { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# The delegation step's marker line: if it appears, the bootstrap reached the
# orchestrator core, which a failure path must never do.
DELEGATION_MARKER="Delegating to the orchestrator core"

# Shared assertions -----------------------------------------------------------

# The run never reached the Tests: no delegation, no test-results anywhere
# under the case's clone dir.
assert_no_tests_ran() { # <log> <cloneDir>
  local log="$1" cloneDir="$2"
  if ! grep -qF "$DELEGATION_MARKER" "$log"; then
    ok "the run never delegated to the orchestrator core"
  else
    bad "the run delegated to the orchestrator core despite the failure"
  fi
  if ! find "$cloneDir" -path '*build/test-results*' 2>/dev/null | grep -q .; then
    ok "no Tests were run (no test-results produced)"
  else
    bad "test results were produced despite the failure"
  fi
}

# Requirement 4.9's halt-BEFORE-clone: the clone dir was never created and no
# clone was even attempted.
assert_halted_before_clone() { # <log> <cloneDir>
  local log="$1" cloneDir="$2"
  if [ ! -e "$cloneDir" ]; then
    ok "halted before any clone (no clone directory created)"
  else
    bad "a clone directory was created despite the pre-clone halt"
  fi
  if ! grep -q "Cloning the Commons_Repository" "$log"; then
    ok "no clone was attempted"
  else
    bad "a clone was attempted despite the configuration failure"
  fi
}

# Run `make test-server` with hermetic overrides; captures output and returns
# make's exit code. Usage: run_test_server <log> VAR=VALUE...
run_test_server() {
  local log="$1"; shift
  "${MAKE[@]}" test-server HARNESS_JAVA_HOME="$JAVA_STUB" "$@" >"$log" 2>&1
}

# Local fixture repo for the clone cases: a valid git repo on branch `main`
# that intentionally is NOT a commons checkout (no esdk/test-server).
fixtureRepo="$scratch/fixture-commons"
git init -q -b main "$fixtureRepo"
echo "this repo is intentionally NOT a valid commons checkout" > "$fixtureRepo/README.md"
git -C "$fixtureRepo" add -A
git -C "$fixtureRepo" -c user.email=it@example.com -c user.name="esdk-it" commit -qm "init"

# ----------------------------------------------------------------------------
# Test A: missing commons-configuration.json halts before any clone (Req 4.9).
# ----------------------------------------------------------------------------
echo "== Test A: missing commons-configuration.json halts before any clone (Req 4.9) =="
logA="$scratch/a.log"
cloneA="$scratch/cloneA"
missingCfg="$scratch/does-not-exist-commons-configuration.json"
if run_test_server "$logA" COMMONS_CONFIGURATION="$missingCfg" CLONE_DIR="$cloneA"; then
  bad "expected a non-zero exit when commons-configuration.json is missing"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "missing or unparseable" "$logA" && grep -qF "$missingCfg" "$logA"; then
  ok "error names the expected commons-configuration.json location"
else
  bad "error does not name the expected commons-configuration.json location"
fi
assert_halted_before_clone "$logA" "$cloneA"
assert_no_tests_ran "$logA" "$cloneA"

# ----------------------------------------------------------------------------
# Test B: corrupt (invalid JSON) commons-configuration.json halts before any
# clone (Req 4.9).
# ----------------------------------------------------------------------------
echo "== Test B: corrupt commons-configuration.json halts before any clone (Req 4.9) =="
logB="$scratch/b.log"
cloneB="$scratch/cloneB"
corruptCfg="$scratch/corrupt-commons-configuration.json"
echo '{ this is not valid JSON !!!' > "$corruptCfg"
if run_test_server "$logB" COMMONS_CONFIGURATION="$corruptCfg" CLONE_DIR="$cloneB"; then
  bad "expected a non-zero exit when commons-configuration.json is corrupt"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "missing or unparseable" "$logB" && grep -qF "$corruptCfg" "$logB"; then
  ok "error names the expected commons-configuration.json location"
else
  bad "error does not name the expected commons-configuration.json location"
fi
assert_halted_before_clone "$logB" "$cloneB"
assert_no_tests_ran "$logB" "$cloneB"

# ----------------------------------------------------------------------------
# Test C: valid JSON without the required commonsRepository entry halts before
# any clone (Req 4.9).
# ----------------------------------------------------------------------------
echo "== Test C: valid JSON lacking commonsRepository halts before any clone (Req 4.9) =="
logC="$scratch/c.log"
cloneC="$scratch/cloneC"
incompleteCfg="$scratch/incomplete-commons-configuration.json"
echo '{ "product": "esdk", "supportedFeatures": [], "unsupportedFeatures": [] }' > "$incompleteCfg"
if run_test_server "$logC" COMMONS_CONFIGURATION="$incompleteCfg" CLONE_DIR="$cloneC"; then
  bad "expected a non-zero exit when commonsRepository is absent"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "missing or unparseable" "$logC" && grep -qF "$incompleteCfg" "$logC"; then
  ok "error names the expected commons-configuration.json location"
else
  bad "error does not name the expected commons-configuration.json location"
fi
assert_halted_before_clone "$logC" "$cloneC"
assert_no_tests_ran "$logC" "$cloneC"

# ----------------------------------------------------------------------------
# Test D: a nonexistent branch halts the run naming the URL and branch
# (Req 4.10). Uses a real local fixture repo so only the branch is bogus.
# ----------------------------------------------------------------------------
echo "== Test D: nonexistent branch halts the run naming URL + branch (Req 4.10) =="
logD="$scratch/d.log"
cloneD="$scratch/cloneD"
bogusBranch="no-such-branch-$$"
fixtureUrl="file://$fixtureRepo"
if run_test_server "$logD" COMMONS_REPO="$fixtureUrl" COMMONS_BRANCH="$bogusBranch" CLONE_DIR="$cloneD"; then
  bad "expected a non-zero exit when the branch does not exist"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "failed to clone" "$logD"; then
  ok "failure output identifies the clone failure"
else
  bad "failure output does not identify the clone failure"
fi
if grep -qF "$fixtureUrl" "$logD" && grep -qF "$bogusBranch" "$logD"; then
  ok "failure names the Commons_Repository URL and the branch"
else
  bad "failure does not name the URL and branch"
fi
assert_no_tests_ran "$logD" "$cloneD"

# ----------------------------------------------------------------------------
# Test E: an unreachable URL halts the run naming the URL and branch
# (Req 4.10). No COMMONS_BRANCH override, so the run exercises the
# configuration-entry branch selection from the REAL commons-configuration.json.
# ----------------------------------------------------------------------------
echo "== Test E: unreachable URL halts the run naming URL + branch (Req 4.10) =="
logE="$scratch/e.log"
cloneE="$scratch/cloneE"
bogusUrl="file:///definitely/not/a/repo"
configuredBranch="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["commonsRepository"]["branch"])' "$TS_DIR/commons-configuration.json")"
if run_test_server "$logE" COMMONS_REPO="$bogusUrl" CLONE_DIR="$cloneE"; then
  bad "expected a non-zero exit when the URL is unreachable"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "failed to clone" "$logE"; then
  ok "failure output identifies the clone failure"
else
  bad "failure output does not identify the clone failure"
fi
if grep -qF "$bogusUrl" "$logE" && grep -qF "$configuredBranch" "$logE"; then
  ok "failure names the Commons_Repository URL and the configured branch"
else
  bad "failure does not name the URL and configured branch"
fi
assert_no_tests_ran "$logE" "$cloneE"

# ----------------------------------------------------------------------------
# Test F: the clone succeeds but lacks the orchestrator core -> the post-clone
# sanity check halts the run naming the URL and branch (Req 4.10).
# ----------------------------------------------------------------------------
echo "== Test F: clone lacking the orchestrator core halts naming URL + branch (Req 4.10) =="
logF="$scratch/f.log"
cloneF="$scratch/cloneF"
if run_test_server "$logF" COMMONS_REPO="$fixtureUrl" COMMONS_BRANCH="main" CLONE_DIR="$cloneF"; then
  bad "expected a non-zero exit when the clone lacks the orchestrator core"
else
  ok "run halted with a non-zero exit"
fi
if grep -q "no orchestrator core" "$logF"; then
  ok "failure output identifies the missing orchestrator core"
else
  bad "failure output does not identify the missing orchestrator core"
fi
if grep -qF "$fixtureUrl" "$logF" && grep -q "branch: main" "$logF"; then
  ok "failure names the Commons_Repository URL and the branch"
else
  bad "failure does not name the URL and branch"
fi
assert_no_tests_ran "$logF" "$cloneF"

echo ""
echo "== Summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
