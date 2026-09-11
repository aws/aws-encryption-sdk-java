# ============================================================================
# ESDK TestServer bootstrap for the aws-crypto-tools-java Language_Repository
# ----------------------------------------------------------------------------
# This repository (aws-crypto-tools-java) is a Language_Repository: it holds
# the live ESDK Java source (../, i.e. esdk/) and, after the relocation, the
# Java Language_Server (esdk/test-server/server/). It does NOT embed the
# cross-language TestServer. The Orchestrator core is hosted in the
# Commons_Repository, so this Makefile is the THIN BOOTSTRAP of the
# bootstrap-then-delegate design (design section "4. Language_Repository
# bootstrap"): it does the minimum needed to reach the core, and everything
# else — validation, source resolution, building + launching every
# Language_Server (including stamping/installing THIS working tree as the live
# ESDK Java library), running the Tests matrix, and reporting — lives in the
# core. The bootstrap plus core together are the single orchestrated entry
# point of Requirement 2.7.
#
# The whole flow is ONE target:
#
#   make test-server [COMMONS_BRANCH=<override>]
#
#     1. Parse commons-configuration.json (the Commons_Configuration_Entry).
#        Missing/unparseable -> halt BEFORE any clone, naming the file
#        (Requirement 4.9).
#     2. git clone --depth 1 --branch <branch> <url> .commons-clone
#        Clone failure / nonexistent branch -> halt naming the URL and branch
#        (Requirement 4.10).
#     3. Run the orchestrator core inside the clone with
#        context=language:java, languageRepoRoot=<this repo root>, and the
#        commonsOrigin.* coordinates. The core uses THIS working tree as the
#        live Java library AND Java server source (Requirement 4.2) and
#        resolves every Other language from the clone's Configuration_Set.
#        The core's exit code is the run result and propagates out of make.
#
# COMMONS_BRANCH=<branch> on the command line is the invocation-time commons
# branch override of Requirement 4.8: the clone uses the supplied branch in
# place of the configured one, and the delegation reports
# commonsOrigin.reason=invocation-override (else configuration-entry).
#
# The old clone-commons-at-head / build-live-esdk / orchestrate-live / run
# targets are gone: the orchestrator's JavaLaunchPlan now stamps and installs
# the live library itself (mvn versions:set -> install -> revert under a
# distinct version), so local and CI runs cannot diverge from the orchestrated
# path.
#
# ----------------------------------------------------------------------------
# COMMONS COORDINATES — SINGLE SOURCE OF TRUTH
# ----------------------------------------------------------------------------
# The Commons_Repository coordinates (name, URL, branch) are the
# Commons_Configuration_Entry and live in ONE place: the `commonsRepository`
# object of `commons-configuration.json` next to this Makefile (Requirement
# 4.4). That file also carries the required `product` field, the Java
# Feature_Declaration (supportedFeatures / unsupportedFeatures), and optional
# configurationOverrides — all consumed by the orchestrator core, not by this
# bootstrap. The file is parsed with python3 (no jq dependency), lazily inside
# the test-server recipe so `make help` / `make clean` work even when it is
# missing — its absence is a hard error for `make test-server` only, reported
# BEFORE any clone (Requirement 4.9).
#
# Until the ESDK TestServer merges to commons `main`, the configured branch
# pins the feature branch `kessplas/esdk-test-server`; flip it back to `main`
# in commons-configuration.json after the merge.
#
# CI note: the workflow authenticates the private commons clone by mapping the
# SSH URL to an HTTPS+PAT URL via `git config url.<...>.insteadOf` before
# invoking this Makefile; the plain `git clone` below picks that up
# automatically, so nothing credential-specific lives here.
#
# NOTE: written for the GNU Make 3.81 that ships with macOS (no .ONESHELL), so
# multi-step recipes run on continued lines as one bash script, mirroring the
# commons esdk/test-server/Makefile.
# ============================================================================

SHELL := bash

# Absolute directory containing this Makefile (works with `make -C`).
MAKEFILE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# The root of this Language_Repository (aws-crypto-tools-java). This is the
# languageRepoRoot handed to the orchestrator core: the core resolves the Java
# library (esdk/) and the Java server (esdk/test-server/server/) from paths
# relative to it (Requirement 4.2), and reads configurationOverrides from
# <languageRepoRoot>/esdk/test-server/commons-configuration.json.
REPO_ROOT := $(abspath $(MAKEFILE_DIR)/../..)

# The Commons_Configuration_Entry carrier (single source of truth, Req 4.4).
COMMONS_CONFIGURATION := $(MAKEFILE_DIR)/commons-configuration.json

# Invocation-time commons branch override (Requirement 4.8). Empty means "use
# the branch configured in commons-configuration.json". Supplying it flips the
# delegation's commonsOrigin.reason to invocation-override.
COMMONS_BRANCH ?=

# Testing convenience ONLY (used by the failure-path integration tests to
# point at a local file:// fixture without network): overrides the clone URL.
# The authoritative URL is the one in commons-configuration.json.
COMMONS_REPO ?=

# Where the fresh clone lands. Kept under a scratch dir ignored by .gitignore
# so the clone is never committed back into this Language_Repository.
CLONE_DIR ?= $(MAKEFILE_DIR)/.commons-clone

# Path to the orchestrator core inside the clone.
CLONE_ORCH_DIR := $(CLONE_DIR)/esdk/test-server/orchestrator

# The relocated Java Language_Server module (task 12.1): handlers, registry,
# config marshalling, protocol, ServerBootstrap, and its jqwik/unit tests.
SERVER_DIR := $(MAKEFILE_DIR)/server

# The commons-hosted Smithy model consumed by the server build (the server
# carries NO model copy; Requirement 1.7). Defaults to the model inside the
# bootstrap clone; `server-test` clones commons first when it is absent.
# Override for local work against a commons working copy, e.g.:
#   make server-test MODEL_DIR=/path/to/aws-crypto-tools-commons/esdk/test-server/model
MODEL_DIR ?= $(CLONE_DIR)/esdk/test-server/model

# --- JDK resolution ----------------------------------------------------------
# The commons harness (smithy-java client/server + orchestrator) requires
# JDK 21+ -> HARNESS_JAVA_HOME, resolved here for the delegation step. The
# live ESDK Java build's own JDK (17-class) is resolved INSIDE the
# orchestrator's JavaLaunchPlan — no ESDK-side JDK is needed here anymore.
#
# HARNESS_JAVA_HOME: honor caller, else try macOS java_home for 23/22/21 and
# require major >= 21, else the known Homebrew JDK 23.
# NOTE: the version is parsed from the line CONTAINING "version" (grep), not
# `head -1`, because a JAVA_TOOL_OPTIONS notice is often printed to stderr
# before the version line and would otherwise be mis-parsed as an empty major
# version.
HARNESS_JAVA_HOME ?= $(shell for c in "$$(/usr/libexec/java_home -v 23 2>/dev/null)" "$$(/usr/libexec/java_home -v 22 2>/dev/null)" "$$(/usr/libexec/java_home -v 21 2>/dev/null)" "/opt/homebrew/Cellar/openjdk/23.0.2/libexec/openjdk.jdk/Contents/Home"; do if [ -n "$$c" ] && [ -x "$$c/bin/java" ]; then v=$$("$$c/bin/java" -version 2>&1 | grep -i version | head -1 | sed -E 's/.*version .?([0-9]+).*/\1/'); if [ -n "$$v" ] && [ "$$v" -ge 21 ] 2>/dev/null; then echo "$$c"; break; fi; fi; done)

.DEFAULT_GOAL := help

.PHONY: help check-harness-java test-server server-test smoke-check it clean

# ----------------------------------------------------------------------------
help: ## Show this help
	@echo "ESDK TestServer — aws-crypto-tools-java Language_Repository bootstrap"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  %-24s %s\n", $$1, $$2}'
	@echo ""
	@echo "The single entry point is 'make test-server': it parses the"
	@echo "Commons_Configuration_Entry, clones commons at the branch head, and"
	@echo "delegates the complete Language_Repository_Run to the orchestrator core"
	@echo "in the clone (this working tree is the live Java library + server)."
	@echo "The KMS scenarios are REQUIRED, so valid AWS credentials must be present."
	@echo ""
	@echo "Commons coordinates (single source of truth: commons-configuration.json):"
	@echo "  COMMONS_CONFIGURATION=$(COMMONS_CONFIGURATION)"
	@if coords=$$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["commonsRepository"]; print(c["name"]); print(c["url"]); print(c["branch"])' "$(COMMONS_CONFIGURATION)" 2>/dev/null); then \
		echo "$$coords" | { read -r n; read -r u; read -r b; \
			echo "  name:   $$n"; \
			echo "  url:    $$u"; \
			echo "  branch: $$b   (design default is 'main'; pinned to the feature branch until merge)"; }; \
	else \
		echo "  <missing or unparseable — 'make test-server' will halt naming this file>"; \
	fi
	@echo ""
	@echo "Variables:"
	@echo "  COMMONS_BRANCH=$(if $(strip $(COMMONS_BRANCH)),$(COMMONS_BRANCH),<unset — use the configured branch>)   (invocation override, Req 4.8)"
	@echo "  CLONE_DIR=$(CLONE_DIR)"
	@echo "  MODEL_DIR=$(MODEL_DIR)   (commons Smithy model for 'server-test')"
	@echo "  REPO_ROOT=$(REPO_ROOT)"
	@echo "  HARNESS_JAVA_HOME=$(if $(strip $(HARNESS_JAVA_HOME)),$(HARNESS_JAVA_HOME),<unresolved — set a JDK 21+>)"

# ----------------------------------------------------------------------------
check-harness-java: ## Verify a JDK 21+ is resolved for the commons harness
	@if [ -z "$(strip $(HARNESS_JAVA_HOME))" ]; then \
		echo "ERROR: could not resolve a JDK 21+ for the commons harness (smithy-java needs 21+)." >&2; \
		echo "       Set one explicitly, e.g.:  make HARNESS_JAVA_HOME=/path/to/jdk21 <target>" >&2; \
		exit 1; \
	fi
	@echo "==> Harness JAVA_HOME=$(HARNESS_JAVA_HOME)"

# ----------------------------------------------------------------------------
# The single orchestrated entry point for this Language_Repository
# (Requirement 2.7): bootstrap (parse + clone) then delegate to the
# orchestrator core in the clone. All three steps run in ONE recipe under
# `set -eo pipefail`, so any failure halts the run and make exits with the
# failing step's code — in particular the core's non-zero exit on a failed run
# propagates out (CI failure semantics, Requirements 6.4/6.8).
test-server: check-harness-java ## Bootstrap + delegate the complete Language_Repository_Run (needs AWS creds); COMMONS_BRANCH=<b> overrides the commons branch
	@set -eo pipefail; \
	\
	: "--- 1. parse the Commons_Configuration_Entry (halt BEFORE any clone: Req 4.9) ---"; \
	if ! coords=$$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["commonsRepository"]; print(c["url"]); print(c["branch"]); print(c["name"])' "$(COMMONS_CONFIGURATION)" 2>/dev/null); then \
		echo "ERROR: the Commons_Configuration_Entry is missing or unparseable." >&2; \
		echo "       expected location: $(COMMONS_CONFIGURATION)" >&2; \
		echo "       It must be valid JSON with a .commonsRepository object containing" >&2; \
		echo "       \"url\", \"branch\", and \"name\" (python3 is required to parse it)." >&2; \
		echo "       Halting before cloning the Commons_Repository: no Tests will run (Requirement 4.9)." >&2; \
		exit 1; \
	fi; \
	{ read -r cfg_url; read -r cfg_branch; read -r cfg_name; } <<< "$$coords"; \
	\
	: "--- select the branch: invocation override (Req 4.8) or the configured entry ---"; \
	if [ -n "$(strip $(COMMONS_BRANCH))" ]; then \
		branch="$(strip $(COMMONS_BRANCH))"; reason="invocation-override"; \
	else \
		branch="$$cfg_branch"; reason="configuration-entry"; \
	fi; \
	url="$(strip $(COMMONS_REPO))"; if [ -z "$$url" ]; then url="$$cfg_url"; fi; \
	\
	: "--- 2. clone commons at the branch head (halt naming URL + branch: Req 4.10) ---"; \
	echo "==> Cloning the Commons_Repository ($$cfg_name) at head of '$$branch' ($$reason)"; \
	echo "    url:    $$url"; \
	echo "    branch: $$branch"; \
	echo "    into:   $(CLONE_DIR)"; \
	rm -rf "$(CLONE_DIR)"; \
	if ! git clone --depth 1 --single-branch --branch "$$branch" "$$url" "$(CLONE_DIR)"; then \
		echo "ERROR: failed to clone the Commons_Repository." >&2; \
		echo "       url:    $$url" >&2; \
		echo "       branch: $$branch" >&2; \
		echo "       The repository may be unreachable or the branch may not exist." >&2; \
		echo "       Halting: no Tests will run (Requirement 4.10)." >&2; \
		exit 1; \
	fi; \
	if [ ! -d "$(CLONE_ORCH_DIR)" ]; then \
		echo "ERROR: the cloned Commons_Repository has no orchestrator core at esdk/test-server/orchestrator." >&2; \
		echo "       url:    $$url" >&2; \
		echo "       branch: $$branch" >&2; \
		echo "       The branch may not contain the ESDK TestServer." >&2; \
		echo "       Halting: no Tests will run (Requirement 4.10)." >&2; \
		exit 1; \
	fi; \
	\
	: "--- 3. delegate to the orchestrator core in the clone (exit code propagates) ---"; \
	echo "==> Delegating to the orchestrator core in the clone"; \
	echo "    context=language:java languageRepoRoot=$(REPO_ROOT)"; \
	echo "    commonsOrigin.url=$$url commonsOrigin.branch=$$branch commonsOrigin.reason=$$reason"; \
	export JAVA_HOME="$(HARNESS_JAVA_HOME)"; \
	cd "$(CLONE_ORCH_DIR)"; \
	./gradlew --console=plain run \
		--args="context=language:java languageRepoRoot=$(REPO_ROOT) commonsOrigin.url=$$url commonsOrigin.branch=$$branch commonsOrigin.reason=$$reason"

# ----------------------------------------------------------------------------
# 12.1: the relocated Java Language_Server's OWN unit/property tests (jqwik +
# JUnit; no AWS credentials, no other Language_Server). The server build
# REQUIRES -PmodelDir pointing at the commons-hosted Smithy model (this repo
# carries no model copy, Requirement 1.7), so when MODEL_DIR is left at its
# default (inside $(CLONE_DIR)) and the model is not already there, this
# target first obtains commons exactly like `test-server` does: parse the
# Commons_Configuration_Entry (halt naming the file), then a depth-1 clone at
# the selected branch head (halt naming URL + branch). CI (the
# Language_Repository_Run workflow) calls this target before `test-server`;
# local runs may skip the clone entirely with
# MODEL_DIR=<commons working copy>/esdk/test-server/model.
server-test: check-harness-java ## Run the Java Language_Server's own unit/property tests (MODEL_DIR=<commons model> to use a local commons)
	@set -eo pipefail; \
	model_dir="$(MODEL_DIR)"; \
	if [ ! -d "$$model_dir" ]; then \
		if [ "$$model_dir" != "$(CLONE_DIR)/esdk/test-server/model" ]; then \
			echo "ERROR: MODEL_DIR does not exist: $$model_dir" >&2; \
			echo "       Point MODEL_DIR at the commons esdk/test-server/model directory." >&2; \
			exit 1; \
		fi; \
		: "--- obtain commons for its model (same bootstrap as test-server) ---"; \
		if ! coords=$$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["commonsRepository"]; print(c["url"]); print(c["branch"]); print(c["name"])' "$(COMMONS_CONFIGURATION)" 2>/dev/null); then \
			echo "ERROR: the Commons_Configuration_Entry is missing or unparseable." >&2; \
			echo "       expected location: $(COMMONS_CONFIGURATION)" >&2; \
			echo "       Cannot locate the commons Smithy model for the server build." >&2; \
			exit 1; \
		fi; \
		{ read -r cfg_url; read -r cfg_branch; read -r cfg_name; } <<< "$$coords"; \
		if [ -n "$(strip $(COMMONS_BRANCH))" ]; then branch="$(strip $(COMMONS_BRANCH))"; else branch="$$cfg_branch"; fi; \
		url="$(strip $(COMMONS_REPO))"; if [ -z "$$url" ]; then url="$$cfg_url"; fi; \
		echo "==> Cloning the Commons_Repository ($$cfg_name) at head of '$$branch' for its Smithy model"; \
		echo "    url:    $$url"; \
		echo "    branch: $$branch"; \
		echo "    into:   $(CLONE_DIR)"; \
		rm -rf "$(CLONE_DIR)"; \
		if ! git clone --depth 1 --single-branch --branch "$$branch" "$$url" "$(CLONE_DIR)"; then \
			echo "ERROR: failed to clone the Commons_Repository." >&2; \
			echo "       url:    $$url" >&2; \
			echo "       branch: $$branch" >&2; \
			exit 1; \
		fi; \
		if [ ! -d "$$model_dir" ]; then \
			echo "ERROR: the cloned Commons_Repository has no model at esdk/test-server/model." >&2; \
			echo "       url:    $$url" >&2; \
			echo "       branch: $$branch" >&2; \
			exit 1; \
		fi; \
	fi; \
	echo "==> Running the Java Language_Server tests (modelDir=$$model_dir)"; \
	export JAVA_HOME="$(HARNESS_JAVA_HOME)"; \
	cd "$(SERVER_DIR)"; \
	./gradlew --console=plain test -PmodelDir="$$model_dir"

# ----------------------------------------------------------------------------
# 15.2: structural smoke check for the shipped factoring — complete
# Commons_Configuration_Entry (Req 4.4), product "esdk" (Req 8.2), the Java
# Feature_Declaration supporting streaming + MPL (Req 8.12), zero copies of
# the Tests definition (Req 10.6), and no standalone feature file (Req 8.2).
# Hermetic: filesystem + python3 only.
smoke-check: ## Run the structural smoke check for this Language_Repository
	@bash "$(MAKEFILE_DIR)/tests/structural_smoke_check.sh"

# ----------------------------------------------------------------------------
# 11.3 + 15.2: the repository's hermetic checks — the bootstrap failure-path
# integration tests (missing/corrupt commons-configuration.json, bogus
# URL/branch — no Tests run in any case) followed by the structural smoke
# check. Both run under `set -e` so a failing suite fails the target.
it: ## Run the bootstrap failure-path integration tests and the structural smoke check
	@set -e; \
	bash "$(MAKEFILE_DIR)/tests/clone_setup_failure_it.sh"; \
	bash "$(MAKEFILE_DIR)/tests/structural_smoke_check.sh"

# ----------------------------------------------------------------------------
clean: ## Remove the commons clone
	@echo "==> Removing commons clone ($(CLONE_DIR))"
	@rm -rf "$(CLONE_DIR)"
