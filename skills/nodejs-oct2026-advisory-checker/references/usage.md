# Node.js October 2026 Security Advisory Version Checker

A dependency-free Node.js security version checker for macOS/Linux, requiring Python 3.9+. It does not scan or execute local programs by default; select a check mode explicitly.

Inspired by [openai/php2shell-checker](https://github.com/openai/php2shell-checker): obtain versions, compare them against pinned rules, and report explicit statuses and exit codes. This is an independent Python implementation. Rules follow the [Node.js October 2026 security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), with fixed versions **22.23.4 / 24.22.1 / 26.12.1**. Lifecycle classification follows the [Node.js Release Schedule](https://github.com/nodejs/Release#release-schedule). The rule date is 2026-10-22; rules do not update automatically over the network.

The linked October 21 bulletin lists ten CVEs, including **CVE-2026-111497** (Brotli decoder out-of-bounds write). Individual CVEs affect different maintained release lines. This tool compares the overall advisory release thresholds only; it does not test each CVE, vendor backports, runtime feature usage, or dependency patches separately.

## Usage

Run from this skill's `scripts/` directory using a trusted Python 3.9+ interpreter:

```sh
# Classify a supplied version without executing Node.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --node-version 24.21.0

# Execute trusted Node on PATH with --version and a sanitized startup environment.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --allow-exec --local

# Scan a selected directory without executing discovered files.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --scan /path/to/directory

# Read all running and stopped local Docker containers without executing container commands.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --docker --json > docker-report.json

# Select a Docker Unix socket explicitly; modes can be combined.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --allow-exec --local --docker \
  --docker-socket /path/to/docker.sock --json > report.json

# Query an explicitly selected, trusted executable; this option can be repeated.
python3 -B -I -S nodejs_oct2026_advisory_checker.py --allow-exec --node /opt/homebrew/bin/node

# Run offline tests.
python3 -B -I -S test_nodejs_oct2026_advisory_checker.py
```

The `--local` and `--node` modes execute the selected program. The user must verify that it is trusted. Both modes require `--allow-exec`; `--node` also requires an absolute path. Execution as root is refused. Clearing environment variables cannot make a malicious executable safe; do not pass unfamiliar files discovered by a scan to `--node`. Static modes only read files and do not write to targets. Reports go to stdout; saving them is the caller's choice.

Docker mode uses only GET requests for `/version`, container lists, container details, and file archives. It requires no Docker CLI, reads no login credentials, does not output container environment variables, and does not use exec, pull, create, start, or stop. It prefers `~/.docker/run/docker.sock` when present, otherwise `/var/run/docker.sock`. It does not use Docker contexts or `DOCKER_HOST`, and does not support remote TCP/SSH. A Docker socket grants powerful access; connect only to a trusted local daemon.

## Results

| patch_status | Meaning | Exit code |
| --- | --- | --- |
| patched_by_version | The observed version meets this advisory's fixed-version threshold | 0 when all results have this status |
| vulnerable_by_version | A supported release line is below the fixed version; vendor backports were not verified | 1 |
| unsupported | The release line is end-of-life as of the rule date | 1 |
| unknown | A read failed, the version is ambiguous or outside the rules, or evidence is insufficient | 3 |

Argument errors exit with 2. Mixed results are summarized in this order: vulnerable, unsupported, unknown, patched. Individual results are always preserved, so exit code 1 may coexist with unverified targets. JSON includes the rule date, sources, timestamp, evidence types, read errors, recommended fixed-version thresholds, and limitations.

If a Docker binary cannot be identified and only headers or `NODE_VERSION` are readable, the final result remains unknown. `metadata_patch_status` classifies only that declared version; it does not prove that the actual runtime is patched.

**`compromise_status` is always `not_assessed`. Version checks cannot establish that a host is free of compromise and do not verify vendor patches, file signatures, or binary integrity.**

## Coverage and limits

- Directory scans match `node`, `nodejs`, and `node.exe`, and intentionally exclude `.git`. Candidate file symlinks and subdirectory symlinks are not followed; each is recorded as unknown. These coverage gaps remain even if other files meet the fixed-version thresholds. The selected root directory may be a symlink. The tool does not bypass macOS privacy controls or elevate system privileges.
- Versions are identified from a unique `node.js/vX.Y.Z` string in an executable, never from arbitrary semver strings. Missing markers, multiple distinct version markers, scripts, non-regular files, or files larger than 256 MiB remain unknown. Version strings can be forged.
- Docker mode checks `/usr/local/bin/node`, `/usr/bin/node`, `/usr/bin/nodejs`, and their container symlink targets, combining results from multiple discovered binaries. Read failures are not treated as patched. Reports include container names, image names, and IDs; redact them before sharing when necessary.
- Docker checks cover common paths in container filesystems. They do not establish that running processes use those files. Custom paths, images without containers, nested Docker, Node embedded in Electron, and historical network records are outside scope.
- Each operation defaults to a 10-second timeout. `--timeout` accepts values greater than 0 and no more than 60 seconds. The separate overall scan deadline is described below; the tool does not retry automatically.
- Finding no Node files does not establish that Node is absent. Permission failures and skipped items remain unverified. These rules cover this advisory only and do not replace a continuously updated vulnerability database or compromise investigation.

To update rules, recheck the official advisory and lifecycle schedule, update `FIXED`, `EOL`, and `RULES_AS_OF`, and run boundary tests. Do not change only the report date.

## Overall scan budgets (1.1.0)

Every CLI invocation uses a POSIX alarm for the scan deadline (60 seconds by default), an entry counter (100,000 by default), and a 512 MiB cumulative read budget. `--max-seconds` accepts values greater than 0 and at most 600; `--max-entries` accepts 1 through 100,000. The JSON `resource_limits` object reports configured limits, observed counters, and `limit_reached`. One extra entry or byte can be observed to establish exhaustion. No automatic retry or budget increase occurs.

Directory entries and archive members count even when they are not candidates. Container/image records also count; LiteLLM log lines count. Selected Node executable queries count as entries. Filesystem enumeration streams entries, and pending directories are bounded by the same counter. Byte accounting includes local files, Docker response bytes, and decompressed wheel candidate bytes; TAR member bytes are already counted in the archive stream.

At a limit, completed findings are preserved and an unknown `resource_limit` result is added. Exit 1 can therefore coexist with incomplete coverage; otherwise exhaustion exits 3. JSON generation happens after the scan timer is stopped. This is not a process-memory limit, an OS sandbox, or a guarantee that an uninterruptible kernel operation will stop promptly. The scripts are CLI tools for macOS/Linux; their internal helpers are not a thread-safe embedding API.

Executable probes close stdin and limit combined stdout/stderr to 4 KiB during collection. `--timeout` bounds the whole probe, including descendants holding its pipes. Cleanup kills the dedicated process group on success, failure, output overflow, or timeout. Descendants that deliberately escape the group are not contained. Root execution is refused. Static binary reads use bounded reads rather than memory mapping, and changing file sizes produce unknown. Docker archive reads accept uncompressed TAR only and stop at 257 MiB of archive bytes, including headers.
