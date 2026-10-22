# Node.js October 2026 Security Advisory Version Checker

A Node.js security version checker and Codex skill for macOS/Linux, requiring Python 3.9+. Tool version: **1.1.0**. Rules are pinned to the October security advisory as of **2026-10-22**.

## What problem does this solve?

After a Node.js security release, checking one `node --version` does not tell you about other copies in selected application directories or Docker containers. This tool helps you identify which observed versions need attention under the pinned advisory and which targets still lack enough evidence.

It answers three specific questions:

- Is an observed Node.js version below the advisory's fixed version: **22.23.4, 24.22.1, or 26.12.1**, depending on its release line?
- Is the release line already end-of-life as of the rule date?
- Which selected targets remain unverified because files cannot be read, version markers are ambiguous, or only metadata is available?

For example, supplying `24.21.0` produces `vulnerable_by_version` with a recommended fixed-version threshold of `24.22.1`. Supplying `24.22.1` produces `patched_by_version` for this advisory. An unreadable or unidentifiable candidate remains `unknown`, so it does not disappear from the report as an apparently safe result.

Use the report to prioritize upgrades and follow up on coverage gaps. It does not upgrade Node, test whether an exploit works, or determine whether a host was compromised. See the [usage guide](skills/nodejs-oct2026-advisory-checker/references/usage.md) for the advisory source and detailed evidence limits.

## Covered advisory and identifiers

Scope: the [Node.js October 21, 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), with rules pinned to **2026-10-22**. The official bulletin lists these ten CVEs. The release lines below are the maintained lines listed as affected in that bulletin; they are not a statement about older, unsupported releases.

| Identifier | Issue described by the advisory | Affected maintained release lines |
| --- | --- | --- |
| CVE-2026-105482 | NUL characters truncate names passed to DNS resolution | 22.x, 24.x, 26.x |
| CVE-2026-105483 | Fullwidth IP digits bypass TLS hostname verification | 24.x, 26.x |
| CVE-2026-106069 | Hostnames that loosely resolve to IP addresses bypass TLS hostname verification | 22.x, 24.x, 26.x |
| CVE-2026-111497 | Brotli decoder out-of-bounds write can permit remote code execution | 22.x, 24.x, 26.x |
| CVE-2026-105481 | Keep-alive sockets process responses written before a request was sent | 22.x, 24.x, 26.x |
| CVE-2026-106072 | Non-canonical IPv4 hostnames allow DNS SANs to authenticate IP endpoints | 22.x, 24.x, 26.x |
| CVE-2026-106074 | Startup snapshots and single executable applications preserve random-value caches | 22.x, 24.x, 26.x |
| CVE-2026-106070 | ZIP processing returns attacker-controlled prefix bytes after failed header validation | 26.x |
| CVE-2026-106071 | Wildcard lookup grants excessive filesystem permissions | 26.x |
| CVE-2026-106073 | fs.realpathSync bypasses the Permission Model | 22.x, 24.x, 26.x |

| Release line | Fixed-version threshold used by this checker |
| --- | --- |
| 22.x | 22.23.4 |
| 24.x | 24.22.1 |
| 26.x | 26.12.1 |

**The checker compares overall release-version thresholds; it does not produce a separate applicability or exploitability verdict for each CVE.** A version below its threshold does not establish that every CVE in the table applies to that runtime. Vendor backports, feature usage, linked dependency versions, and binary integrity are not verified. The bulletin also includes dependency updates, which this checker does not inspect individually. Unsupported release lines are reported according to the pinned lifecycle rules; other unrecognized release lines remain unknown. This is not a continuously updated vulnerability scanner.

## Supported checks

Compare a supplied version, scan a selected directory without executing discovered files, query a trusted executable, or inspect standard paths in local Docker containers. The tool assesses version risk; it cannot establish whether a system has been compromised. The `--local` and `--node` modes execute the trusted program you select.

## Codex skill

This repository includes the independently installable [nodejs-oct2026-advisory-checker skill](skills/nodejs-oct2026-advisory-checker/SKILL.md). Give this repository's GitHub URL to Codex's `$skill-installer` and ask it to install `skills/nodejs-oct2026-advisory-checker`. Alternatively, copy that entire directory into your user skills directory.

Example prompts:

```text
$nodejs-oct2026-advisory-checker Check Node.js version risk in /selected/directory.
$nodejs-oct2026-advisory-checker Compare Node 24.21.0 with the fixed versions in the October advisory.
```

## Run directly

Run from the repository root using a verified, trusted Python interpreter. Examples for macOS:

```sh
/usr/bin/python3 -B -I -S skills/nodejs-oct2026-advisory-checker/scripts/nodejs_oct2026_advisory_checker.py --node-version 24.21.0 --json
/usr/bin/python3 -B -I -S skills/nodejs-oct2026-advisory-checker/scripts/nodejs_oct2026_advisory_checker.py --scan /path/to/directory --json
```

On other systems, use the absolute path to a trusted Python 3.9+ interpreter. See the [usage guide](skills/nodejs-oct2026-advisory-checker/references/usage.md) for Docker mode, trusted executable queries, exit codes, and coverage limits. Rules do not update automatically. Exit code 0 only means the observed versions meet this advisory's fixed-version thresholds.

## Safety and resource limits

Use a verified Python 3.9+ interpreter with `-B -I -S`, outside the environment under investigation. No report certifies a clean host. Reports can contain local paths, container names, and image references; inspect them before sharing.

Each CLI run defaults to a **60-second overall scan deadline**, **100,000 entries**, and a **512 MiB cumulative read budget**. Use `--max-seconds` (greater than 0, at most 600) and `--max-entries` (1 to 100,000) to choose a smaller or explicitly longer scan. Directory enumeration streams entries instead of loading every filename at once. Reaching a budget stops further checks, retains completed observations, and adds an unknown `resource_limit` finding. A known risk can still produce exit 1; otherwise an incomplete check exits 3. Inspect `resource_limits.limit_reached` and individual results.

These are application limits, not a hard process-memory limit or an OS security sandbox. A one-byte probe may exceed the read budget to detect exhaustion. Parsing has overhead, and uninterruptible kernel operations can delay the alarm or cleanup. The deadline covers scanning, not final JSON serialization or the caller's output destination. Do not use elevated privileges just to expand coverage.

**Execution is disabled unless `--allow-exec` accompanies `--local` or `--node`.** These modes run the selected program with your privileges. Use them only for an executable you already trust; use `--scan` or `--node-version` for incident triage. `--node` requires an absolute path, and executable probes are refused as root. The flag acknowledges execution risk; it does not establish trust.

The probe closes stdin, clears the inherited environment, and limits stdout plus stderr to **4 KiB while reading**. Timeout, excess output, or an invalid banner produces unknown. Cleanup kills the probe's process group, including children that still hold its output pipes. A malicious program can still access files or the network and can escape its process group; these protections do not make untrusted execution safe. Static scans never execute discoveries. Node binary reads are capped at 256 MiB; Docker file archives are uncompressed TAR streams capped at 257 MiB, including overhead.

## Offline tests

```sh
/usr/bin/python3 -B -I -S skills/nodejs-oct2026-advisory-checker/scripts/test_nodejs_oct2026_advisory_checker.py
```

The tests use harmless local subprocess fixtures and simulated Docker responses. No live Docker daemon is required. The execution tests run only their own disposable shell fixtures.

## Repository layout

```text
skills/nodejs-oct2026-advisory-checker/
  SKILL.md
  agents/openai.yaml
  scripts/nodejs_oct2026_advisory_checker.py
  scripts/test_nodejs_oct2026_advisory_checker.py
  references/usage.md
```

This repository works independently and does not depend on another checker. Its structure was inspired by OpenAI's php2shell-checker. The code is an independent implementation, not an official OpenAI product.

## License

[MIT](LICENSE). Copyright (c) 2026 Frankisfrank.
