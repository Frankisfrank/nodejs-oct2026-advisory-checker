---
name: nodejs-oct2026-advisory-checker
license: MIT
description: Check selected local or Docker Node.js runtimes against the October 2026 security advisory using the bundled checker with static checks and explicitly enabled trusted-program queries. Use for Node.js version-risk checks and interpreting their coverage; does not establish compromise or infer a runtime from a website URL.
---

# Node.js October 2026 Security Advisory Version Checker

Use the bundled `scripts/nodejs_oct2026_advisory_checker.py` (1.1.0), read its JSON, and report version risk and coverage gaps. Rules are pinned to 2026-10-22. A version check does not establish that a system was never compromised or that every vulnerability has been fixed.

The fixed scope is the October 21, 2026 Node.js security bulletin, including CVE-2026-111497 and the other nine listed CVEs. Report advisory-level version risk, not ten individually verified vulnerabilities. The bulletin's affected release lines differ by CVE. See the [usage guide](references/usage.md) for the source and evidence limits.

## Execution boundary

`--allow-exec` is required for `--local` and `--node`; it is not evidence that the target is safe. Static modes remain the default choice for suspect environments. Execution uses a cleared environment, closed stdin, a 4 KiB combined stdout/stderr cap, and process-group cleanup. A malicious executable still has the user's file and network access and may escape the process group. Do not describe these controls as isolation.

## Select scope and mode

- Preserve the user's selected directories, versions, or Docker scope. If the request only says to check Node without a target, first locate Node on PATH; do not expand to the entire host, all containers, or remote systems. A website URL cannot establish the actual Node version.
- Use `--node-version` to compare a supplied version and `--scan` to read a directory. Discovered files are not executed. Use `--node` or `--local` only after the user explicitly authorizes execution and identifies the selected executable as trusted. Both require `--allow-exec`; `--node` requires an absolute path. Never add that flag merely to work around a rejected command. Never pass files discovered during an incident scan to either execution mode. Both modes refuse root execution.
- Docker mode enumerates every container on the selected local daemon, including running and stopped containers. Use it only when that scope is authorized. It cannot filter to one container and does not inspect unused images or nested daemons. Do not describe its results as verification of the versions used by running processes.
- Use a known trusted Python 3.9+ interpreter outside the environment being investigated, with `-B -I -S`. Paths below are relative to this skill directory. When invoking the tool, an absolute script path may be used; quote user paths correctly.

```sh
/usr/bin/python3 -B -I -S scripts/nodejs_oct2026_advisory_checker.py --node-version 24.21.0 --json
/usr/bin/python3 -B -I -S scripts/nodejs_oct2026_advisory_checker.py --scan /selected/directory --json
/usr/bin/python3 -B -I -S scripts/nodejs_oct2026_advisory_checker.py --allow-exec --node /trusted/path/to/node --json
/usr/bin/python3 -B -I -S scripts/nodejs_oct2026_advisory_checker.py --docker --docker-socket /selected/docker.sock --json
```

Use the example system interpreter on macOS only after verifying that it is trusted. On other systems, substitute the absolute path to a verified interpreter. Read the [usage guide](references/usage.md) when selecting Docker mode or interpreting evidence types; it documents arguments, fixed-version thresholds, and mode-specific limits.

## Resource budgets

The CLI defaults to 60 seconds, 100,000 entries, and 512 MiB of cumulative reads. `--max-seconds` accepts (0, 600]; `--max-entries` accepts [1, 100000]. Preserve `resource_limits.limit_reached` and the unknown resource-limit result. Do not automatically retry, raise budgets, or switch to execution mode after exhaustion. Select smaller targets or change a budget only within the user's authorized scope. Completed findings remain meaningful; unvisited targets remain unverified. These limits are not a process-memory cap or a sandbox. Read the [usage guide](references/usage.md) for format and per-input limits.

## Connections and results

Before the first Docker connection, verify the execution host, intended Unix socket, and network policy. If the sandbox is known to block access, use the narrowest supported approval path without retrying through the blocked path. The tool performs a read-only `/version` preflight. A connection failure does not establish daemon downtime or invalid credentials. Do not restart services, switch sockets, or reset credentials to bypass a failure.

Read stdout JSON and the process exit code. Do not automatically retry because the tool exits with 1 or 3:

| Result | Interpretation |
| --- | --- |
| 0 / patched_by_version | Observed versions meet this advisory's thresholds; vendor backports, integrity, and running processes were not verified |
| 1 / vulnerable_by_version or unsupported | Version risk is present; also inspect all results for unknown entries |
| 3 / unknown | Some targets remain unverified; do not describe them as patched or absent |
| 2 or no valid JSON | The invocation did not complete; report the error without a security verdict |

Report the selected targets, observed versions and evidence sources, risk, unknown or skipped targets, and applicable rule date. Distinguish metadata versions from binary evidence and preserve the meaning of `compromise_status=not_assessed`. If the user asks about current risks, check official or vendor advisories and explain differences from the pinned rules separately; do not silently change the rules. This skill does not automatically perform upgrades, service repairs, or compromise investigations.

After maintaining the script, run `python -B -I -S scripts/test_nodejs_oct2026_advisory_checker.py`, replacing `python` with the same trusted interpreter. Tests use offline fixtures only.
