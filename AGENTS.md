# Repository Guidelines

Notes for AI agents and contributors working **in this repository**. The human-facing
overview is [README.md](README.md) (Chinese) / [README.en.md](README.en.md) (English); dense
contracts, invariants and workflow live here.

## What this repo is

A Go library that runs **one child process** with a kernel-enforced filesystem/network view
derived from an **ordered rule table handed in by the caller**. vbox owns rule evaluation,
platform enforcement and process supervision. Callers own config parsing, approvals, grant
lifetimes and audit. Module path `github.com/veypi/vbox`; dependencies limited to
`golang.org/x/sys` and `golang.org/x/text` (no cgo, no `replace` in `go.mod`) — third parties
must be able to `go get` it as-is. Reference caller: `aic-pod` `libs/host`.

## Build, test, verify

```sh
go test ./...
go vet ./...
GOOS=windows go vet ./...   # vet type-checks test files too
GOOS=linux go vet ./...
gofmt -l .
```

- Sandbox behavior needs a **real host**: Seatbelt on macOS, `bwrap` + usable user
  namespaces on Linux, a real token and object handles for the Windows ACL cases. A
  cross-`GOOS` compile is not evidence of runtime behavior — write "not verified" instead of
  "passes".
- Windows ACL coverage exists **only** on a real Windows machine; CI builds but does not run
  it. Record any manual Windows run (host, tree, result) in the handoff summary. The Windows
  working copy in this environment is `C:\Users\v\aic\vboxtest\vbox-src` (pushed file-by-file
  over the `scp` channel); that copy may carry CRLF line endings, so `gofmt -l` there reports
  line-ending noise rather than formatting drift.

## Invariants (do not change without an explicit decision)

- **First-wins is the whole semantics**: rows are scanned front to back, the first match
  decides; `Class` only groups rows while concatenating and is ignored by matching. Do not
  add "specificity" or override layers.
- **Fail-closed**: an unexpressible rule is rejected at compile time; a host with no usable
  sandbox backend returns an error and the command does **not** run. Never add a silent
  unsandboxed fallback, and never let an approval at the caller side relax enforcement here.
- **Canonical pattern contract**: `Match` normalizes the path side only, so a rule pattern
  must already be canonical. `NewFSRuleSet` / `CompileFSRules` do that normalization; a
  hand-built `FSRuleSet` must not bypass it (on Windows a non-canonical `rw` row makes the
  writable root look read-only and the child is denied write access to its own workspace).
- **`IneffectiveRows` stays conservative**: report only rows an earlier `rw` row provably
  covers (identical pattern, `/**` prefix, bare-path subtree); never report a case that
  relies on guessing glob containment, and never fail compilation because of a dead row.
- **Windows deny-ACE model**: deny/ro rows get a persistent explicit deny ACE; `rw` targets
  get none; the ACE is *not* revoked when the process exits (descendants may outlive the
  launcher) and reconciliation happens through the state file.
- **Windows capability SID names must not be renamed** (`aic-windows-sandbox` derived SIDs).
  Renaming orphans every ACE already written on disk into an unreclaimable state; the name is
  an internal identifier and does not affect users.
- **Neutral runtime artifacts**: state file default `{UserConfigDir}/vbox/sandbox/...`
  (overridable with `Manager.SetStateDir`), private temp prefix `vbox-sandbox-*`. Keep the
  library brand-neutral and free of references to other products.
- **Platform matrix**: darwin / linux / windows are the supported surface; other Unix targets
  compile but fail closed with no backend; plan9 and js/wasip1 must fail at the package
  boundary (sentinel files `unsupported_plan9.go` / `unsupported_wasm.go`). Do not add
  platform claims without real verification.
- **Process contract**: `RunProcess` is the only entry point; cancellation via `ctx` kills
  the whole tree; `Argv0` is display-only; `RawOutput` keeps bytes and disables Windows text
  transcoding; text mode never closes the caller's writers; `Workdir` grants nothing.

## Test conventions

- Environment-capability helpers live in `testenv_test.go`: `requirePOSIXShell`,
  `requireSymlink`, `trivialArgv`. A case that needs host capability must `t.Skip` with a
  stated reason when the capability is missing — never let an environment difference show up
  as a failure.
- Test files for the Windows backend are `*_windows_test.go` (implicit `GOOS` suffix). In
  them, always build rule tables through `canonRules(...)` / `NewFSRuleSet` /
  `CompileFSRules`; bare `Rule{...}` literals with OS-native paths are what broke those cases
  on Windows before (see the canonical pattern contract).
- Compare paths in `/` form (`filepath.ToSlash`) or via the package's canonical helpers; raw
  `filepath.Join` expectations fail on Windows.
- Adding a rule-evaluation change means adding a case to the rule/decision tests, plus a
  platform-specific case when the enforcement differs by backend.

## Docs conventions

- `README.md` is **Chinese** and is the repo's main, human-facing entry point: what it is, quick
  start, rules, platform support, process contract, what is intentionally out of scope.
  `README.en.md` is the English mirror; both start with a language switcher line and must be
  updated together.
- Keep editorial detail (invariants, file-by-file maps, verification workflow) out of the
  READMEs — that belongs in this file.
- `CHANGELOG.md` records user-visible behavior, breaking changes first; `VERSION` holds the
  current version. Review `git status` before committing; tags are created locally only and
  pushed only on explicit instruction.

## Commits

Short imperative subjects scoped to one change (e.g. `sandbox: dedupe shadowed deny rows`).
Explain user-visible behavior and note any platform that was only build-verified.
