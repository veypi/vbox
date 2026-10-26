# vbox

**A native subprocess sandbox for Go.** Start a child process on a real host with a
kernel-enforced view of what it may read, write and connect to — expressed as one ordered
rule table.

[中文](README.md) | **English**

```go
code, err := mgr.RunProcess(ctx, vbox.StartOptions{
	Exec:    []string{"/usr/bin/curl", "-sS", "https://api.example.com/x"},
	Workdir: "/srv/work",
	Policy:  policy, // ordered fs/net rule snapshot
}, nil, os.Stdout, os.Stderr)
```

vbox does one thing: it takes a rule snapshot from *your* code and makes the operating
system enforce it for one child process. Configuration parsing, approvals, grant lifetimes
and audit all stay in the caller — vbox never reads your config and never decides policy.

This document describes the current rule contract. Manager snapshot caching and the
darwin deny-posture egress proxy are implemented; real-host acceptance and remaining
work are tracked in [docs/development/todo.md](docs/development/todo.md).

## What you get

- **One ordered rule table using `level + original order`.** Higher levels match first;
  rows at the same level keep first-match-wins table order. There is no specificity rule or
  implicit override layer, and `Class` never derives a level.
- **Kernel enforcement, not emulation.** macOS Seatbelt (SBPL), Linux bubblewrap, Windows
  restricted token + explicit deny ACEs. Pure Go, no cgo (`golang.org/x/sys` + `x/text`).
- **Fail-closed.** A rule this platform cannot express is rejected before anything starts;
  a host without a usable sandbox backend reports an error and the command is *not* run.
  There is no silent fallback to running unsandboxed.
- **Process supervision included.** Whole-tree cancellation via `context`, output capture
  (text or raw bytes), environment scrubbing, resource limits, optional stage timing logs.
- **Decide without running.** The same rule table answers "may this process write
  `/srv/work/out.txt`?" as a pure function — useful for pre-flight checks and tests.

## Install

```sh
go get github.com/veypi/vbox
```

See [go.mod](go.mod) for the required Go version.

## Quick start

```go
rules, err := vbox.CompileFSRules([]string{
	"ro:~/.ssh/known_hosts", // read-only
	"deny:**/.ssh/**",       // no read, no write (the line above already made known_hosts an exception)
	"rw:/srv/work/**",       // read + write
}, vbox.ClassCfg)
if err != nil {
	return err // not expressible on this platform: refuse, do not widen
}

policy := vbox.Policy{
	FS: vbox.NewFSRuleSet(rules, vbox.EffDeny), // unmatched writes denied (reads stay open)
	Net: vbox.NetRuleSet{
		Rules:   []vbox.NetRule{{HostPort: "api.example.com:443", Allow: true}},
		Default: false, // deny posture; per-row landing semantics in "Network rule enforcement"
	},
}

mgr := vbox.NewManager()
defer mgr.Close(ctx) // terminates every child still running

code, err := mgr.RunProcess(ctx, vbox.StartOptions{
	Exec:    []string{"/usr/bin/curl", "-sS", "https://api.example.com/x"},
	Workdir: "/srv/work",
	Policy:  policy,
}, nil, os.Stdout, os.Stderr)
```

Ask the table directly when you only want a decision:

```go
d := policy.FS.Match("/srv/work/out.txt", vbox.OpWrite)
// d.Allow, d.Matched (matched row index, -1 = fell through to the default), d.Effect, d.Level

allow := policy.Net.Match("api.example.com:443")
```

`Match` follows a trailing symlink (open/connect semantics); `MatchNoFollow` is for
`unlink`/`rename`, where the link itself is the target. `MatchPath` takes an
already-normalized path and never touches the host filesystem.

## Rule table

Each leading `!` adds one level (0–255), before the effect prefix; for example,
`!!deny:/secret` is a level-2 deny row. `Class` never derives a level.

Effects, in the order they usually appear in a table:

| Prefix | Meaning |
| --- | --- |
| `deny:` | deny read and write |
| `ro:` | allow read, deny write |
| `rw:` | allow read and write |

Patterns: a bare path covers its whole subtree (`/srv/work` covers `/srv/work/a/b`);
`*` matches within one segment, `?` one character, `**` matches zero or more segments
(so `/etc/ssh/**` also matches `/etc/ssh` itself). Matching compares level first; rows at
the same level are scanned front to back and the first match decides.

`Class` (`ClassTemp` / `ClassCfg` / `ClassBuiltin` / `ClassConvenience`) only exists so a
caller can concatenate rows from different sources in a stable order (temp grants → config →
built-in defaults → convenience roots). Matching ignores `Class` and never derives a level
from it.

### Two rules that bite

**Priority matters, and a shadowed row is silent.** If a higher-priority `rw:` row already
covers a `deny:` / `ro:` target, that covered row can never match — the execution side simply
allows it. Higher levels win first; earlier rows win within one level. Call
`IneffectiveRows(rules)` at assembly time to get the indexes of rows that a higher-priority
`rw` row fully covers (the check is conservative: it only reports cases it can prove statically,
and it never fails compilation). With `Manager.SetLogf` set, the execution path also logs a
`shadowed by a higher-priority rw row` line.

**Build tables with `NewFSRuleSet` / `CompileFSRules`, not with struct literals.** A
hand-built `FSRuleSet` must carry canonical patterns: `Match` normalizes the *path* side on
entry, so a pattern written in another spelling is compared across two namespaces and
quietly stops matching. On Windows that turns a writable root into a read-only target and
the child loses write access to its own workspace. Both constructors normalize patterns for
you (`CompileFSRules` also expands variables and rejects rules this host cannot enforce).

## Platform support

| Platform | Status |
| --- | --- |
| macOS (arm64 / amd64) | **Supported** — Seatbelt backend; built and fully tested in CI |
| Linux (amd64 / arm64) | **Supported** — bubblewrap backend (needs `bwrap` and usable user namespaces); built and fully tested in CI |
| Windows (amd64 / arm64) | **Supported** — restricted token + explicit deny ACEs; built in CI, ACL cases need a real Windows host |
| freebsd / netbsd / openbsd / dragonfly / solaris / illumos / aix / android | Not promised — compiles, no kernel backend (fail-closed), no behavioral verification |
| plan9 / js / wasip1 | **Unsupported** — process, signal and sandbox semantics are missing; the build fails explicitly at the package boundary |

Anything not listed counts as "not promised". How each backend maps the same table:

| Platform | Mechanism | Notes |
| --- | --- | --- |
| macOS | Seatbelt (SBPL profile) | Profile is emitted in reverse `level + original-order` priority (SBPL lets later rules win); `ro` rows also sink an explicit write denial, so read-only holes inside writable roots are enforced by the kernel |
| Linux | bubblewrap | Whole-machine read-only view plus bindings for terminal writable roots; `ro`/`rw` holes are re-added from terminal decisions; requires `bwrap` and user namespaces |
| Windows | Restricted token + deny ACEs | Handle-based ACL (`\\?\` long paths, `Get/SetSecurityInfo`); targets that resolve to `rw` get no ACE, `deny` and standalone `ro` rows get a deny ACE; an effective nested read-only hole that cannot be enforced reports unsupported before launch |
| Other | No kernel sandbox | Explicit error, never a silent unsandboxed run |

### Network rule enforcement

Network rules land differently from filesystem rules — posture and per-row rules are
separate:

| Platform | Posture (`Default`) | Per-row rules |
| --- | --- | --- |
| macOS | deny combines the Seatbelt full-block posture with the built-in egress proxy; open keeps its previous behavior | Loopback rows use Seatbelt; under deny, non-loopback rows use the HTTP/SOCKS5 proxy with the complete snapshot. Under open, an unenforceable selective deny still aborts launch |
| Linux | Kernel-enforced (deny = `--unshare-net`; the new netns leaves loopback unconfigured, so even loopback is unreachable) | Not expressible |
| Windows | open only; the deny posture aborts the launch outright | Not expressible |

Rows the kernel cannot express are handled by direction — **the sandbox never ends up
wider than the policy**:

- **deny rows**: dropping one would widen the sandbox, so the launch is refused
  (fail-closed).
- **allow rows**: under Linux deny they may be *absorbed* because the target is already
  unreachable. Under darwin deny, non-loopback allows are enforced by the proxy instead
  of being absorbed. Under open, omitting an allow that cannot land only narrows the
  result. On darwin, winning loopback rows are enforced by the kernel.
- **No execution-layer markers**: rules describe only the child process FS/NET targets;
  execution-layer prefixes and fields are rejected. If the active backend cannot enforce
  an effective rule, it reports "unsupported" and refuses to launch; it never drops the
  rule, reroutes execution, or substitutes another execution layer.

Rule patterns support strict subdomain wildcards such as `*.example.com` (not the bare
domain or IP literals). `localhost`, `.localhost` subnames and loopback IPs form one
canonical class; `*.localhost` matches that class.

Use `CheckNetPolicy(platform, rules)` to pre-flight a table: it classifies every row as
`Kernel` / `Proxy` / `Absorbed` / `Reserved`. Syntax errors and `UnsupportedError` are
distinct; an unsupported capability rejects only the dependent process launch and never
rewrites policy semantics. Static preflight and darwin Seatbelt emission share `compileNetPlan`.

### Built-in darwin egress proxy

The endpoint starts only for `confined && darwin && NetRuleSet.Default == false`. Open and
`NoSandbox` neither create an endpoint nor inject proxy variables. Two loopback-only
listeners provide HTTP `CONNECT` / plain HTTP absolute-form and SOCKS5 `CONNECT`. Each
endpoint has an independent random authentication token. Only TCP is forwarded; TLS is
not terminated and UDP is unsupported.

- The launch plan emits highest-priority Reserved loopback transport rules for both
  listener ports. Final targets still use the complete immutable policy snapshot, while
  direct loopback access remains governed by Seatbelt.
- Upper- and lowercase `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are forced last;
  `ALL_PROXY` uses `socks5h://`. `NO_PROXY` / `no_proxy` are merged and include
  `127.0.0.1,localhost,::1`; caller `Env` cannot replace the internal endpoint.
- `NetRuleSet.UpstreamProxy` explicitly selects an `http://`, `socks5://` or `socks5h://`
  upstream. It is part of netKey; ambient host proxy variables are never inherited.
- Domains are resolved before each concrete IP is authorized. Private, loopback,
  link-local, metadata and local-interface addresses cannot be allowed by a domain row;
  they need a matching IP/loopback row. Downstream connections use only the authorized
  IP, so an upstream proxy cannot re-resolve the domain into a different address.
- Endpoints are built once per netKey and reused within a Manager. Process completion
  releases the lease; the default idle grace period is 30s, active requests/tunnels are
  not idle-evicted, and `Manager.Close` closes listeners, connections and handlers.

The token is not an isolation boundary against a malicious same-UID process that can read
another process environment. Stronger isolation requires a separate OS user or broker.

On Windows, idempotent deny-ACE bookkeeping is kept in a state file (default
`{UserConfigDir}/vbox/sandbox/deny_acl_state.json`; override with `Manager.SetStateDir`),
and capability SIDs are derived deterministically — so ACEs stay stable across calls and
restarts and no other process on the host is affected.

**A write root that cannot be granted an ACL only degrades that root — it never sinks the
whole exec.** The directory may not exist yet (filtered at spawn time), or it may exist yet be
un-grantable — typically owned by `Administrators`/`SYSTEM` while the current user only holds
`Modify`, which excludes changing the security descriptor. Such a root is read-only inside the
sandbox and is reported once per directory in the log (stable marker
`write-root unavailable in sandbox`); the remaining writable roots and the exec itself are
unaffected. Granting is retried on every call, so fixing the ACL (or recreating the directory)
restores writability automatically. Callers can predict the same thing at grant time with
`CheckFSGrantTarget(abs)` (native path required). The opposite direction never degrades: a
`deny` target that cannot be enforced still aborts the run — the sandbox must never end up
wider than the policy.

## Process management

`RunProcess` is the only entry point; `Manager.Close` terminates every child still running.

- **Environment**: by default the scrubbed host environment plus your `Env` overrides;
  `ReplaceEnv` makes `Env` the complete environment (empty list = empty environment).
- **`Argv0`**: changes the displayed name only — it never affects path lookup or identity,
  and a sandbox launcher that cannot support it reports an error instead of ignoring it.
- **`RawOutput`**: keeps stdout/stderr as raw bytes with write errors, disabling Windows
  text transcoding and line buffering — for protocol pipes and binary commands. The default
  text mode flushes only the wrappers it created itself and never closes your writers.
- **`Workdir`**: sets the working directory only; it grants no permissions.
- **Cancellation and deadlines**: entirely via `ctx`; cancelling kills the whole process
  tree (Job Object on Windows).
- **Logging**: `SetLogf` receives sandbox/execution stage timings (and the shadowed-row
  notice above); without it the whole path is silent.
- **State directory**: `SetStateDir(dir)` picks where persistent state lives (the Windows
  deny-ACE state file; default `{UserConfigDir}/vbox/sandbox`).

## What is not here

Config parsing, default rule sources, session grants, grant lifetimes, approvals,
command registration and scheduling are all outside this library. vbox receives an
FS/NET snapshot, decides, and enforces it for a native child process. It neither
describes nor depends on any particular caller or integration layer.

## Testing

```sh
go test ./...
go vet ./...
```

Sandbox cases need real platform capabilities: Seatbelt on macOS, `bwrap` plus user
namespaces on Linux, a real token and object handles for the Windows ACL cases. Cases skip
themselves (with a stated reason) when the host cannot provide what they need — a
cross-`GOOS` compile proves nothing about runtime behavior.

## Docs, version, license

- Documentation map: [docs/index.md](docs/index.md).
- Behavior changes: [CHANGELOG.md](CHANGELOG.md); current version: [VERSION](VERSION).
- Contributor and AI-agent notes, including the invariants that must not be broken:
  [AGENTS.md](AGENTS.md).
- MIT — see [LICENSE](LICENSE).
