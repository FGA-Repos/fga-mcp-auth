# FGA Org CI Standard

## As-built (2026-08-25)

This doc is the **rationale record** for FGA's GitHub Actions setup. It is not a
generator: **each repo's own `.github/workflows/ci.yml` is authoritative.** When a
template here and a shipped workflow disagree, the shipped workflow wins and this
doc is stale — fix the doc.

Rolled out to 11 repos, all green on the versions below:

| GitHub repo | Local dir | Shape |
|---|---|---|
| `FGA-Repos/fga-mcp-auth` | `fga-mcp-auth` | §2 dual-SDK matrix, locked (`uv run --locked`) |
| `FGA-Repos/fga-automation-bot` | `fga-bot` | §1 Workflow A, activated-venv, dummy `env:` |
| `FGA-Repos/fga-basecamp-mcp-tools` | `fga-doc-search` | §1 Workflow A, `setup-python` variant |
| `FGA-Repos/stoplightapp` | `SLA` | §3 Django variant |
| `FGA-Repos/fga-quorum-mcp` | `fga-quorum-mcp` | §1 Workflow A (MCP uniform) |
| `FGA-Repos/fga-congress-mcp` | `fga-congress-mcp` | §1 Workflow A (`tests/unit` scope) |
| `FGA-Repos/fga-regulations-mcp` | `fga-regulations-mcp` | §1 Workflow A (MCP uniform) |
| `FGA-Repos/fga-fec-mcp` | `fga-fec-mcp` | §1 Workflow A (MCP uniform) |
| `FGA-Repos/fga-nonprofits-mcp` | `fga-nonprofits-mcp` | §1 Workflow A (MCP uniform) |
| `FGA-Repos/fga-teamtailor-mcp` | `fga-teamtailor-mcp` | §1 Workflow A (MCP uniform) |
| `FGA-Repos/fga-ob3-mcp` | `fga-ob3-mcp` | §1 Workflow A (MCP uniform) |

### Pinned action versions (the whole allow-list)

| Action | Pin | Why this form |
|---|---|---|
| `actions/checkout` | `@v5` | Node 24. First-party, publishes floating major tags — major tag is fine. |
| `astral-sh/setup-uv` | `@v10.0.1` | Node 24. **Exact patch, not `@v10`** — see below. |
| `actions/setup-python` | `@v6` | Node 24. Only used by `fga-basecamp-mcp-tools`; floating major tag is fine. |

**Why `setup-uv` is pinned to an exact patch.** From **v8.0.0** astral-sh switched
to GitHub immutable releases and **stopped publishing major and minor tags** as an
anti-supply-chain-attack measure (the tj-actions incident). `refs/tags/v8`, `v9`,
`v10` simply do not exist — `astral-sh/setup-uv@v10` fails to resolve at job start.
The floating-major convention this doc used through v7 is therefore not available
on this action, and the pin has to move by hand. Bump it deliberately, in its own
commit, across all 11 repos at once so the fleet stays uniform.

`v10.0.1` = commit `20cfd1bf945f4377ade1205e4dbc17946fc9a30d`, if you ever want to
tighten to a SHA.

### setup-uv v6 → v10 breaking surface, and how it landed here

- **v8.0.0 — no more major/minor tags.** The one change that actually bit. Handled
  by pinning `@v10.0.1`. Also removed the deprecated `manifest-file` format; we
  never used it.
- **v8.1.0 — `no-project` became a real input.** Under v6 it was an unrecognized
  key and silently ignored; now it appends `--no-project` to the `uv venv` call.
  It **only has an effect together with `activate-environment: true`**, which is
  exactly how all 8 repos that pass it use it. No behavior change observed: the
  step still creates the venv, the pinned `python-version` still governs the
  interpreter, and the subsequent `uv pip install` is unaffected. Repos on the
  `uv run --isolated --group ...` pattern (`fga-mcp-auth`) don't pass it at all.
- **v9.0.0 — `prune-cache` default flipped to `false`** (to spare PyPI). Means
  slightly larger Actions caches, no workflow change. Accepted as-is; revisit only
  if cache storage ever becomes a real cost line.
- **v10.0.0 — `enable-cache: auto` now disables caching on `pull_request_target`,
  `workflow_run`, and `release`** (cache-poisoning defense). **Not applicable** —
  every workflow in the fleet triggers only on `push` to a protected branch and
  plain `pull_request`, both of which still cache. If a workflow ever gains one of
  those three triggers, expect a cold install, not a failure.

**Expected benign annotation.** v10 tries an astral mirror before GitHub Releases;
the mirror currently 404s, so every run logs one notice —
`Failed to download from mirror, falling back to GitHub Releases: Unexpected HTTP
response: 404`. It is a notice, not a warning or a failure, and the fallback works.
Don't chase it.

**The Node 20 deprecation annotation is gone fleet-wide** — that was the point of
the bump. Verified zero `Node.js 20 is deprecated` annotations across all 11 repos'
first post-bump runs.

---

## PEP 668 amendment (2026-08-25, post-rollout — CANONICAL)
`uv pip install --system` FAILS on ubuntu-24.04: setup-uv's `python-version:` yields an
externally-managed interpreter ("The interpreter at /usr is externally managed"). All three
Workflow-A first runs failed on it. Canonical fix, proven green on fga-automation-bot:
give setup-uv `activate-environment: true` and `no-project: true`, drop `--system`, and
`uv pip install` into the activated venv. (Equivalent alternative, proven on
fga-basecamp-mcp-tools: add `actions/setup-python@v6` and let setup-uv do uv+cache only —
use it when matching a Dockerfile's exact interpreter matters.) Every `uv pip install`
line in this doc assumes the activated-venv pattern. Repos using `uv run --isolated
--locked --group ...` (pyproject dependency-groups, e.g. fga-mcp-auth) are unaffected.

One canonical workflow, two variants, one application table. Filename is always
`.github/workflows/ci.yml`, job name always `ci` — matrix repos surface as
`ci (<leg>)` (e.g. `ci (sdk1)`, `ci (sdk2)`), so branch-protection rules and
status checks read the same across the org. `uv` does all installs (fast, cached
via `astral-sh/setup-uv`, whose cache auto-enables on GitHub-hosted runners); no
marketplace actions beyond the three in the pin table above. `setup-uv` installs
the pinned Python itself (`python-version` input), so `actions/setup-python` is
not needed — allowed where a repo needs a non-externally-managed interpreter for
`--system` installs (only `fga-basecamp-mcp-tools` does).

Principles (non-negotiable):
- CI runs only what the repo actually has. No invented test suites, no deps
  added to the service itself — ruff is installed by the workflow when it isn't
  a project dev-dep, never added to `requirements.txt` for CI's sake.
- Workflow-installed ruff is **pinned** (`ruff==0.15.13` fleet-wide today — the
  version those repos lint clean under; bump deliberately in its own PR).
  Unpinned ruff means a new ruff minor can redden every repo with zero repo
  change. Repos that carry ruff in their own dev extras keep that as the source
  of truth instead.
- Zero real secrets in CI. Any env vars a suite needs are static dummy strings
  in the workflow's `env:` block. If a suite can't go green on dummies, it
  self-skips (all current suites already do).
- Green means green. A repo whose lint is red today gets the pre-existing
  findings fixed in the same PR that adds CI — never a softened/`continue-on-error`
  lint gate that trains everyone to ignore it.
- Every workflow carries `permissions: contents: read` (least privilege — CI
  only reads the repo) and a `concurrency` block that cancels stale PR runs on
  new pushes but lets `main`/`staging`/`master` runs finish.
- `runs-on: ubuntu-24.04`, not `ubuntu-latest` — the label will silently migrate
  to a new image someday; pin it and bump on purpose. GitHub warns loudly well
  before an image is retired.

---

## 1. Workflow A — canonical Python service template

Parameterized only by: `PYTHON` version, install line, lint paths, test command,
and an optional `env:` block of dummy vars. Everything else is identical in
every repo. This is the shape the 7 MCP repos and `fga-automation-bot` ship.

```yaml
# .github/workflows/ci.yml
name: ci

on:
  push:
    branches: [main, staging]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  ci:
    runs-on: ubuntu-24.04
    env:
      # <dummy env vars the test suite needs to construct settings — fake strings only>
      # WEBHOOK_SECRET: test
    steps:
      - uses: actions/checkout@v5

      # v8+ stopped publishing floating major tags (immutable releases) — pin the exact patch
      - uses: astral-sh/setup-uv@v10.0.1
        with:
          python-version: "3.12"        # <- param: match .python-version / Dockerfile
          activate-environment: true    # PEP 668: /usr interpreter is externally managed
          no-project: true              # effective only alongside activate-environment
          cache-dependency-glob: |
            **/pyproject.toml
            **/requirements*.txt
            **/uv.lock

      - name: Install
        run: uv pip install -e ".[dev]"   # <- param: or -r requirements.txt 'ruff==0.15.13'

      - name: Lint
        run: |
          ruff check .                   # <- param: paths; config comes from the repo
          ruff format --check .          # only where the repo is already format-clean

      - name: Test
        run: pytest                      # <- param: repo's real test command
```

Notes:
- `push: [main, staging]` + bare `pull_request` covers every PR regardless of
  base, without double-running feature-branch pushes. Repos with a `master`
  default (stoplightapp) substitute `master` for `main`; repos with no `staging`
  (all 7 MCP repos, fga-doc-search) list `main` alone.
- The `concurrency` expression cancels superseded runs only for PR events —
  pushes to protected branches always run to completion, so a rapid pair of
  merges can't leave `main` with a cancelled (unknown) status.
- `cache-dependency-glob` is set explicitly because setup-uv's default only
  watches `**/requirements*.txt` and `**/uv.lock` — pyproject-only repos would
  never invalidate the cache on a dependency change. (uv's cache is a package
  store, so a stale key costs cold-install time, not correctness — this is a
  speed fix, not a safety one.)
- `ruff format --check` is included only where the repo is already format-clean
  (fga-mcp-auth, fga-doc-search). Repos never formatted with ruff (fga-bot,
  stoplightapp, the MCP repos) get `ruff check` only — adding a format gate there
  means a whole-repo reformat commit first, which is a separate decision, not a
  CI default.
- For `requirements.txt` repos, pinned ruff is appended to the install line
  (`uv pip install -r requirements.txt 'ruff==0.15.13'`) because it is
  not and must not become a service dependency.

### 1a. `setup-python` sub-variant (fga-basecamp-mcp-tools only)

Where matching the Dockerfile's exact interpreter matters and the install wants
`--system`, drop `python-version` from setup-uv and let `actions/setup-python`
provide a non-externally-managed interpreter:

```yaml
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"        # matches Dockerfile python:3.12-slim

      - uses: astral-sh/setup-uv@v10.0.1
        with:
          cache-dependency-glob: |
            **/pyproject.toml
            **/requirements*.txt
            **/uv.lock

      - name: Install
        run: uv pip install --system -e ".[dev]" 'ruff==0.15.13'
```

## 2. Variant — fga-mcp-auth (dual-SDK matrix, locked)

The package must pass under both MCP SDK lines; `[tool.uv] conflicts` makes
sdk1/sdk2 mutually exclusive, so they are two isolated resolutions, never one
env. Lint runs in both legs — it's seconds of ruff on an already-resolved dev
group, and keeping everything in one matrixed `ci` job preserves the org-wide
check-name invariant (`ci (sdk1)`, `ci (sdk2)`) instead of sprouting separate
`lint`/`test` checks that branch protection can't key on uniformly.

```yaml
# .github/workflows/ci.yml
name: ci

on:
  push:
    branches: [main]        # single-writer repo: no staging, direct commits to main
  pull_request:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  ci:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        sdk: [sdk1, sdk2]
    steps:
      - uses: actions/checkout@v5

      # v8+ stopped publishing floating major tags (immutable releases) — pin the exact patch
      - uses: astral-sh/setup-uv@v10.0.1
        with:
          python-version: "3.12"          # requires-python is >=3.11; pin so CI can't float
          cache-suffix: ${{ matrix.sdk }} # legs resolve different groups — separate cache keys
          cache-dependency-glob: "**/pyproject.toml"

      - name: Lint
        run: |
          uv run --isolated --locked --group dev ruff check .
          uv run --isolated --locked --group dev ruff format --check .

      - name: Test
        run: uv run --isolated --locked --group dev --group ${{ matrix.sdk }} pytest
```

(`cache-suffix` avoids the two legs racing to save the same cache key — that
race only produces a "cache already exists" warning, but it also means one leg's
packages never get cached; the suffix fixes both. `fail-fast: false` so a break
in one SDK line still reports the other leg's real result.)

**Locked CI — the pattern, now shipped.** `uv.lock` used to be gitignored here, so
every run re-resolved fresh and an upstream release could redden CI with no repo
change. Both halves shipped together, and both halves are required:

1. **Commit `uv.lock`** and drop it from `.gitignore`.
2. **Every `uv run` in CI takes `--locked`**, which fails the run if the lock is
   stale rather than silently re-locking past it.

A committed lock that CI re-locks past buys nothing, and `--locked` without a
committed lock can't work — this is one change, not two. The payoff is that an
unexpected red now means "our code broke", not "the internet moved"; upstream
drift shows up only when someone runs `uv lock` on purpose. Other repos in the
fleet install from `requirements.txt` or extras and are not on this pattern; port
it to any repo that adopts pyproject dependency-groups.

## 3. Variant — stoplightapp (Django, no pytest)

The repo has plain Django `TestCase`s and a purpose-built hermetic settings
module; CI must use it — default settings crash on `DATABASE_NAME=None` before
a single test runs.

```yaml
# .github/workflows/ci.yml
name: ci

on:
  push:
    branches: [master, staging]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  ci:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5

      # v8+ stopped publishing floating major tags (immutable releases) — pin the exact patch
      - uses: astral-sh/setup-uv@v10.0.1
        with:
          python-version: "3.12"   # matches Dockerfile python:3.12-slim
          cache-dependency-glob: "**/requirements*.txt"

      # NOTE: not `uv pip install --system`. On ubuntu-24.04 the runner's own
      # python3.12 IS the 3.12 uv resolves to, and it is PEP 668
      # externally-managed, so --system fails outright. Install into a venv and
      # put it on PATH so the Lint/Test steps stay plain commands.
      - name: Install
        run: |
          uv venv --python 3.12 --allow-existing .venv
          echo "$PWD/.venv/bin" >> "$GITHUB_PATH"
          uv pip install --python .venv/bin/python -r requirements.txt -r requirements-mcp.txt 'ruff==0.15.13'

      - name: Lint
        run: ruff check .          # requires the ruff.toml added in the CI PR

      - name: Test
        run: python manage.py test --settings=stoplight.settings_test
```

`mysqlclient` in requirements.txt needs `libmysqlclient` headers on the runner;
the pinned `ubuntu-24.04` image ships them (`default-libmysqlclient-dev` is
preinstalled), and pinning the image freezes that preinstall set — if a future
image bump ever drops it, add one
`apt-get install -y default-libmysqlclient-dev` step rather than swapping the
driver. Tests themselves run on in-memory SQLite via `settings_test`, no MySQL
server needed.

Shipped with the CI PR, a minimal `ruff.toml` (repo had none):

```toml
# ruff.toml
extend-exclude = ["**/migrations/**"]
```

Migration boilerplate is generated code; linting it is noise (standard Django
practice). Everything else (E402 in import scripts, F405 in settings_test, the
dead `stoplight_app/urls.py` F821s, the unused stub import) got fixed, not
excluded — see the table.

---

## 4. Per-repo application table — ROLLOUT-ERA RECORD (historical)

> **Read this as history, not as current state.** The "pre-existing red" and
> "not recon'd" columns describe each repo *before* CI was wired; those findings
> were fixed in the rollout PRs and the columns are kept only so the reasoning
> behind each repo's choices is recoverable. For what a repo runs *today*, read
> its `.github/workflows/ci.yml`. Action versions in this section are superseded
> by the pin table at the top.

### Workflow A services (4)

| Repo (GitHub) | Python | Install | Lint command | Test command | Pre-existing red to fix for green | PR base branch |
|---|---|---|---|---|---|---|
| `FGA-Repos/fga-automation-bot` | **3.13** (`.python-version`; note local venv drifted to 3.14 — don't chase "works on my machine" deltas) | `uv pip install -r requirements.txt 'ruff==X.Y.Z'` (pin = version repo lints clean under) | `ruff check app tests` (no format gate — repo never ruff-formatted) | `pytest` — **requires dummy env**: workflow `env:` block sets fake strings for all 8 required `Settings` fields (`BASECAMP_ACCESS_TOKEN`, `BASECAMP_ACCOUNT_ID`, `BASECAMP_BOT_USER_ID`, `BASECAMP_DEFAULT_PROJECT_ID`, `BASECAMP_DEFAULT_TODOLIST_ID`, `ANTHROPIC_API_KEY`, `DATABASE_URL=postgresql://test`, `WEBHOOK_SECRET=test`), otherwise 36 errors from module-level `Settings()` in `app/main.py` | **16 ruff findings** (3 auto-fixable). Fix all in the CI PR. ⚠️ Flag the 4× F821 to Jacob separately — `commentary.py:443 ArticleContent`, `upload.py:101-102 LLMParser/ActivityStorage`, `article_extractor.py:373 Callable` are likely real missing-import bugs, fix ≠ suppress. Also: **`staging` branch must be created from `main` first** — it doesn't exist yet | `staging` (create it; feature → staging → main. Never main) |
| `FGA-Repos/fga-mcp-auth` | **3.12** (pinned via setup-uv; `requires-python = ">=3.11"` alone lets CI float) | `uv run --isolated` per leg (variant §2) | `uv run --isolated --group dev ruff check .` + `ruff format --check .` — both clean today; runs in both matrix legs (ruff pinned in the `dev` group, not the workflow) | Matrix: `uv run --isolated --group dev --group sdk1 pytest` and `…--group sdk2 pytest` (354p/25s and 357p/22s, green) | None. Open decision: commit `uv.lock` + switch to `uv run --locked` — **RESOLVED, shipped; see §2** | **Direct commit to `main`** — single-writer package repo, PR flow explicitly waived |
| `FGA-Repos/fga-basecamp-mcp-tools` (dir `fga-doc-search`) | **3.12** (Dockerfile `python:3.12-slim`) | `uv pip install -e ".[dev]" 'ruff==X.Y.Z'` (ruff not in dev extras — pin it in the workflow) | `ruff check .` + `ruff format --check .` (format already clean) | `pytest` (117 passed, 0.3s, fully mocked, zero secrets) | **2 ruff findings**: `basecamp_tools.py:909` E741 (rename `l`) and `server.py:153` E402 — the late import looks like deliberate registration-order/circular-import avoidance: confirm with Jacob, then either reorder or `# noqa: E402` with a why-comment. Separate flag: open PAPERCUTS entry says DO `deploy_on_push` silently didn't fire on this repo once — CI green ≠ deployed | `main` (PR) |
| `FGA-Repos/stoplightapp` (dir `SLA`) | **3.12** (Dockerfile) | `uv pip install -r requirements.txt -r requirements-mcp.txt 'ruff==X.Y.Z'` | `ruff check .` with new `ruff.toml` excluding `**/migrations/**` | `python manage.py test --settings=stoplight.settings_test` (27 tests, hermetic, green; **never** bare `manage.py test`) | With migrations excluded, remaining findings to fix: **delete dead `stoplight_app/urls.py`** (2× F821, confirmed unreferenced — `ROOT_URLCONF` is `stoplight.urls`), remove unused `TestCase` import in stub `stoplight_app/tests.py`, fix/`noqa` 3× E402 in `import_reforms.py`/`import_sources.py`/`stoplight/settings.py` and 2× F405 in `settings_test.py` | `staging` (exists; default is `master`) |

### MCP repos (7) — Workflow B consumes this

All seven are uniform: hatchling `pyproject.toml`, `requires-python = ">=3.11"`,
`[dev]` extras already containing pytest + pytest-asyncio + **ruff**, `[tool.ruff]`
config in pyproject, `asyncio_mode = "auto"`, Dockerfile `python:3.12-slim`.
So they all take Workflow A verbatim with: Python **3.12**, install
`uv pip install -e ".[dev]"` (ruff comes from the extras — no workflow
pin needed; the repo's own extras govern its version), lint `ruff check .`
(config in pyproject; no format gate unless verified clean), and `pytest` —
except the two with a unit/integration split. Suites are secrets-free by design
(fga-mcp-auth-style offline conftest); if any leg turns out to need a live API
key, that leg self-skips — never wire a secret.

| Repo | Test command | Lint | Notes / pre-flight before wiring |
|---|---|---|---|
| `FGA-Repos/fga-quorum-mcp` | `pytest` | `ruff check .` | Not recon'd for green — run lint+tests locally first; fix any red in the CI PR |
| `FGA-Repos/fga-congress-mcp` | `pytest tests/unit` | `ruff check src tests` | **Has CI already** (`test.yml`, pip-based, 3.11/3.12 matrix). Replace with standard `ci.yml`, keep `tests/unit` scope (`tests/integration` is deliberately excluded — leave it that way), drop the version matrix (single 3.12 per Dockerfile), delete `test.yml` in the same PR so there's one status check |
| `FGA-Repos/fga-regulations-mcp` | `pytest` | `ruff check .` | Not recon'd for green — verify locally first |
| `FGA-Repos/fga-fec-mcp` | `pytest` | `ruff check .` | Smallest suite (one test file). Not recon'd — verify |
| `FGA-Repos/fga-nonprofits-mcp` | `pytest` (testpaths=tests; only `tests/unit` exists, picked up automatically) | `ruff check .` | Not recon'd — verify |
| `FGA-Repos/fga-teamtailor-mcp` | `pytest` | `ruff check .` | Not recon'd — verify. PII-redaction tests are the ones that matter here |
| `FGA-Repos/fga-ob3-mcp` | `pytest` | `ruff check .` | `test_db.py` present — confirm it self-skips without `DATABASE_URL` (pattern used elsewhere in the org); if it doesn't, gate it with a skipif in the CI PR, don't provision a DB |

All 7 MCP repos: PR base branch is `main` (none has `staging`). In the event, CI
shipped on each repo's existing `feat/fga-mcp-auth` branch rather than a fresh
one, so the CI change rides with the auth work.

---

## 5. Non-goals (explicit)

- **No JS repo coverage.** No JS/TS repo in scope has a test suite; CI there
  would be a fake green. Revisit only when one grows real tests.
- **No coverage thresholds or coverage upload.** Green/red on lint + tests is
  the whole contract. Coverage gates on a one-maintainer org are ceremony.
- **No deploy steps in CI.** DigitalOcean App Platform owns deploys
  (`deploy_on_push`); CI is a gate, not a pipeline. No `doctl`, no build/push,
  no DO tokens — and remember CI green ≠ deployed (the doc-search papercut).
- **No secrets in CI, ever.** Not as GH Actions secrets, not in workflow files.
  Dummy strings satisfy every current suite; suites needing live creds self-skip.
- **No new tooling.** No pre-commit, no mypy, no dependabot config, no
  version-matrix builds beyond fga-mcp-auth's SDK matrix. Add later only when a
  concrete failure motivates it.
- **No merges by agents.** CI PRs are opened for humans to merge (base per the
  table). fga-mcp-auth alone takes direct commits to `main`.

---

## 6. Maintenance — how to bump an action version

There is no dependabot (deliberate, §5). Action bumps are a manual fleet sweep:

1. Read the release notes for every major you're crossing, not just the target.
   The v6→v10 sweep crossed three breaking releases and only one of them
   (v8's dropped major tags) needed a workflow edit — but you can't know that
   without reading all three.
2. Check the tag actually exists: `gh api repos/<owner>/<action>/git/ref/tags/<tag>`.
   A 404 means that pin form isn't published; fall back to the exact patch tag.
3. **Canary on `fga-mcp-auth` first** — single-writer, direct-push, and its dual-SDK
   matrix is the most demanding shape in the fleet. Both legs green *and* the
   annotation list clean before fanning out.
4. Fan out to the other 10 on their existing open branches. Never commit CI
   changes straight to a consumer repo's `main`/`master`/`staging`.
5. Confirm each repo's `ci` check is green on the new head before calling it done.
   Fix or revert per repo; never leave one red.

---

## Review log

External review (codex, 2026-08) — disposition of each finding:

Applied:
- Pinned ruff in every workflow install line (`ruff==0.15.13` at wiring time — the version the repo lints clean under) — unpinned ruff was the likeliest source of a red build with no repo change.
- Added `concurrency` (cancel-in-progress for PR events only) to all three templates.
- fga-mcp-auth variant restructured to a single matrixed `ci` job (`ci (sdk1)`/`ci (sdk2)`) — the old `lint`+`test` jobs broke the doc's own check-name invariant; lint now runs in both legs, and the intro prose states the matrix naming explicitly.
- Pinned `python-version: "3.12"` in the fga-mcp-auth variant — bare `requires-python = ">=3.11"` let CI float with runner/uv changes.
- `uv.lock` recommendation now includes switching to `uv run --locked` in the same PR — a committed lock CI re-locks past buys nothing. **Shipped**; see §2.
- Added `permissions: contents: read` to all templates.
- Added explicit `cache-dependency-glob` (the action's default omits `pyproject.toml`) — noted it's a speed fix, not correctness (uv's cache is a package store).
- Added `cache-suffix: ${{ matrix.sdk }}` to the fga-mcp-auth matrix — same-key cache-save race is only a warning, but it also means one leg never caches.
- `ubuntu-24.04` replaces `ubuntu-latest` everywhere — zero-cost drift protection; also stabilizes stoplight's `libmysqlclient` preinstall reliance.

Rejected at the time, **partly overtaken by events**:
- SHA-pinning `actions/checkout`/`astral-sh/setup-uv`: rejected as conflicting with the no-dependabot rule. Still the position for `checkout` and `setup-python`, which keep floating major tags. For `setup-uv` the choice was made upstream — from v8 there is no major tag to float on, so it now carries an exact patch pin (`@v10.0.1`) and moves by hand. Not a SHA, but the same manual-bump cost the rejection was trying to avoid; see §6.
- Pinning setup-uv's `version:` (uv itself): unchanged — floating uv within a pinned action major is the accepted tradeoff, and "unexpected red → triage as upstream moved first" still applies to every repo except fga-mcp-auth, which is now locked (§2).
- "No-marketplace-actions rule is overbuilt": it's a zero-cost guardrail against exactly the secret-bearing/deploy-action class the standard bans elsewhere; kept.
- Explicit `default-libmysqlclient-dev` apt step for stoplightapp: conscious call with a documented one-line fallback, and the applied `ubuntu-24.04` pin freezes the image's preinstall set — adding the step now is belt-and-suspenders the doc already declined.
