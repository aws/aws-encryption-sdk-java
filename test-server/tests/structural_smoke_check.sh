#!/usr/bin/env bash
# ============================================================================
# Structural smoke check — aws-crypto-tools-java Language_Repository (task 15.2)
# ----------------------------------------------------------------------------
# Asserts the shipped factoring of the ESDK TestServer as seen from THIS
# Language_Repository:
#
#   * Requirement 4.4: commons-configuration.json carries a complete
#     Commons_Configuration_Entry — a `commonsRepository` object whose `name`,
#     `url`, and `branch` are all non-empty strings.
#   * Requirement 8.2 (+ 8.11 groundwork): the same file carries the required
#     `product` field with the exact value "esdk" — the Feature_Declaration
#     lives HERE, alongside the Commons_Configuration_Entry, not in any
#     standalone feature file.
#   * Requirement 8.12: the Java Feature_Declaration lists both "streaming"
#     and "MPL" in `supportedFeatures`, and neither appears in
#     `unsupportedFeatures`.
#   * Requirement 10.6: this Language_Repository contains ZERO copies of the
#     Tests definition — no directory matching the commons Tests module layout
#     (no esdk/test-server/tests/src, no Gradle build under tests/) and no
#     MaterialsRoundTripTests.java anywhere in the repository.
#   * Requirement 8.2 (shape): NO standalone feature-configuration file exists
#     anywhere under esdk/ — the declaration is folded into
#     commons-configuration.json.
#
# Hermetic: no network, no JDK, no AWS — pure filesystem + python3 JSON
# assertions. The bootstrap's commons clone (.commons-clone/), integration
# scratch (.it-tmp/), .git/, and the vendored third-party submodules
# (esdk/submodules/) are excluded from the repository-wide scans: they are not
# part of this Language_Repository's own factoring.
#
# Usage:  bash tests/structural_smoke_check.sh    (or `make -C .. smoke-check`)
# Exit code is non-zero if any assertion fails.
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$(cd "$HERE/.." && pwd)"          # aws-crypto-tools-java/esdk/test-server
REPO_ROOT="$(cd "$TS_DIR/../.." && pwd)"  # aws-crypto-tools-java
CONFIG="$TS_DIR/commons-configuration.json"

pass=0
fail=0
ok()  { echo "  PASS: $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL: $1"; fail=$((fail + 1)); }

# Repository-wide scans skip these (not part of this repo's own factoring).
# Usage: repo_find <find-args...> — a find over $REPO_ROOT with the prunes.
repo_find() {
  find "$REPO_ROOT" \
    \( -name .git -o -name .commons-clone -o -name .it-tmp \
       -o -path "$REPO_ROOT/esdk/submodules" \) -prune \
    -o "$@" -print 2>/dev/null
}

# ----------------------------------------------------------------------------
# Check 1: complete Commons_Configuration_Entry (Req 4.4)
# ----------------------------------------------------------------------------
echo "== Check 1: commons-configuration.json carries a complete Commons_Configuration_Entry (Req 4.4) =="
if [ ! -f "$CONFIG" ]; then
  bad "commons-configuration.json is missing (expected at $CONFIG)"
else
  ok "commons-configuration.json exists"
  if entry_errors=$(python3 - "$CONFIG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
repo = cfg.get("commonsRepository")
errors = []
if not isinstance(repo, dict):
    errors.append("commonsRepository object is missing")
else:
    for key in ("name", "url", "branch"):
        value = repo.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"commonsRepository.{key} is missing or empty")
print("\n".join(errors))
sys.exit(1 if errors else 0)
PY
  ); then
    ok "commonsRepository carries non-empty name, url, and branch"
  else
    if [ -n "$entry_errors" ]; then
      bad "incomplete Commons_Configuration_Entry: ${entry_errors//$'\n'/; }"
    else
      bad "commons-configuration.json is not parseable JSON"
    fi
  fi
fi

# ----------------------------------------------------------------------------
# Check 2: product is exactly "esdk" (Req 8.2, groundwork for the 8.11 match)
# ----------------------------------------------------------------------------
echo "== Check 2: product field is exactly \"esdk\" (Req 8.2) =="
if [ -f "$CONFIG" ] && product=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1])).get("product"); sys.exit(1) if not isinstance(p, str) else print(p)' "$CONFIG" 2>/dev/null); then
  if [ "$product" = "esdk" ]; then
    ok "product is exactly \"esdk\""
  else
    bad "product is \"$product\", expected exactly \"esdk\""
  fi
else
  bad "commons-configuration.json is missing, unparseable, or lacks a string product field"
fi

# ----------------------------------------------------------------------------
# Check 3: Java Feature_Declaration lists streaming + MPL + hierarchical as
# supported (Req 8.12)
# ----------------------------------------------------------------------------
echo "== Check 3: Java Feature_Declaration supports streaming, MPL, and hierarchical (Req 8.12) =="
if [ -f "$CONFIG" ] && feature_errors=$(python3 - "$CONFIG" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
supported = cfg.get("supportedFeatures")
unsupported = cfg.get("unsupportedFeatures")
errors = []
if not isinstance(supported, list):
    errors.append("supportedFeatures array is missing")
if not isinstance(unsupported, list):
    errors.append("unsupportedFeatures array is missing")
if not errors:
    for feature in ("streaming", "MPL", "hierarchical"):
        if feature not in supported:
            errors.append(f'"{feature}" is not in supportedFeatures')
        if feature in unsupported:
            errors.append(f'"{feature}" appears in unsupportedFeatures')
print("\n".join(errors))
sys.exit(1 if errors else 0)
PY
); then
  ok "supportedFeatures lists streaming, MPL, and hierarchical; unsupportedFeatures lists none of them"
else
  if [ -n "${feature_errors:-}" ]; then
    bad "Feature_Declaration violation: ${feature_errors//$'\n'/; }"
  else
    bad "commons-configuration.json is missing or unparseable"
  fi
fi

# ----------------------------------------------------------------------------
# Check 4: zero copies of the Tests definition in this repo (Req 10.6)
# ----------------------------------------------------------------------------
echo "== Check 4: no Tests definition in this Language_Repository (Req 10.6) =="
if [ ! -e "$TS_DIR/tests/src" ]; then
  ok "no esdk/test-server/tests/src directory (no commons Tests module layout)"
else
  bad "esdk/test-server/tests/src exists — looks like a copy of the commons Tests module"
fi
gradle_in_tests=$(find "$TS_DIR/tests" \( -name "build.gradle*" -o -name "settings.gradle*" \) 2>/dev/null)
if [ -z "$gradle_in_tests" ]; then
  ok "no Gradle build under esdk/test-server/tests/ (shell scripts only)"
else
  bad "Gradle build files under esdk/test-server/tests/: ${gradle_in_tests//$'\n'/, }"
fi
tests_copies=$(repo_find -type f -name "MaterialsRoundTripTests.java")
if [ -z "$tests_copies" ]; then
  ok "no MaterialsRoundTripTests.java anywhere in the repository"
else
  bad "Tests definition copy found: ${tests_copies//$'\n'/, }"
fi

# ----------------------------------------------------------------------------
# Check 5: no standalone feature-configuration file under esdk/ (Req 8.2)
# ----------------------------------------------------------------------------
echo "== Check 5: no standalone feature file under esdk/ (Req 8.2) =="
feature_files=$(repo_find -type f -path "$REPO_ROOT/esdk/*" \
  \( -iname "*feature*.json" -o -iname "*feature*.yml" -o -iname "*feature*.yaml" \
     -o -iname "*feature*.toml" -o -iname "*feature*.properties" -o -iname "*feature*.cfg" \))
if [ -z "$feature_files" ]; then
  ok "no standalone feature-configuration file (the declaration lives in commons-configuration.json)"
else
  bad "standalone feature file(s) found: ${feature_files//$'\n'/, }"
fi

echo ""
echo "== Summary: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
