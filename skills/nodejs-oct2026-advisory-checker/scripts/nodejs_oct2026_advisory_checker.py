#!/usr/bin/env python3
"""Check versions against the 2026-10-21 Node.js advisory; no exploit probes."""
import argparse
import contextvars
import datetime
import http.client
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import selectors
import socket
import signal
import time
import stat
import subprocess
import sys
import tarfile
import urllib.parse

TOOL_VERSION = "1.1.0"
ADVISORY = "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"
RULES_AS_OF = "2026-10-22"
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
EOL = set(range(22)) | {23, 25}
MAX_BYTES = 256 * 1024 * 1024
MAGICS = {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
          b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe",
          b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
NODE_NAMES = {"node", "nodejs", "node.exe"}
BINARY_PATHS = ("/usr/local/bin/node", "/usr/bin/node", "/usr/bin/nodejs")
HEADER_PATHS = ("/usr/local/include/node/node_version.h", "/usr/include/node/node_version.h")


# Each repository is standalone; keep these small budget helpers local.
_ACTIVE_BUDGET = contextvars.ContextVar("scan_budget", default=None)


class ScanLimit(Exception):
    """The selected scan is incomplete; already collected evidence stays valid."""


class ScanBudget:
    def __init__(self, seconds=60, entries=100000, byte_limit=512 * 1024 * 1024):
        self.seconds, self.max_entries, self.byte_limit = seconds, entries, byte_limit
        self.entries = self.bytes_read = 0
        self.limit = None

    def stop(self, reason):
        self.limit = self.limit or reason
        raise ScanLimit(self.limit)

    def account(self, entries=0, byte_count=0):
        if self.limit:
            raise ScanLimit(self.limit)
        self.entries += entries
        self.bytes_read += byte_count
        if self.entries > self.max_entries:
            self.stop("Scan entry limit reached")
        if self.bytes_read > self.byte_limit:
            self.stop("Cumulative read limit reached")
        if time.monotonic() >= self.deadline:
            self.stop("Scan time limit reached")

    def __enter__(self):
        self.deadline = time.monotonic() + self.seconds
        self.token = _ACTIVE_BUDGET.set(self)
        self.old_handler = signal.signal(signal.SIGALRM, self.expired)
        self.old_timer = signal.setitimer(signal.ITIMER_REAL, self.seconds)
        return self

    def expired(self, signum, frame):
        self.stop("Scan time limit reached")

    def __exit__(self, kind, value, traceback):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)
        if self.old_timer[0]:
            elapsed = self.seconds - max(0, self.deadline - time.monotonic())
            signal.setitimer(signal.ITIMER_REAL, max(0.000001, self.old_timer[0] - elapsed), self.old_timer[1])
        _ACTIVE_BUDGET.reset(self.token)
        return kind is ScanLimit


def account(entries=0, byte_count=0):
    budget = _ACTIVE_BUDGET.get()
    if budget is not None:
        budget.account(entries, byte_count)



def read_size(requested):
    account()
    budget = _ACTIVE_BUDGET.get()
    if budget is None:
        return requested
    # One extra byte detects that the budget is insufficient without a large read.
    return min(requested, max(1, budget.byte_limit - budget.bytes_read + 1))


def walk_entries(root, onerror):
    # Stream each directory instead of allocating an unbounded os.walk file list.
    pending = [Path(root)]
    while pending:
        account()
        base = pending.pop()
        try:
            with os.scandir(base) as stream:
                for entry in stream:
                    account(entries=1)
                    path = Path(entry.path)
                    linked = entry.is_symlink()
                    is_dir = entry.is_dir(follow_symlinks=False)
                    yield path, is_dir, linked
                    if is_dir and entry.name != ".git":
                        pending.append(path)
        except OSError as exc:
            onerror(exc)


class BoundedReader:
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size=-1):
        account()
        if self.remaining <= 0:
            raise ValueError("Container archive byte limit reached")
        size = min(size if size >= 0 else self.remaining, self.remaining)
        data = self.stream.read(read_size(size))
        self.remaining -= len(data)
        account(byte_count=len(data))
        return data


def classify(version):
    """A version assessment, never evidence of absence of compromise."""
    match = re.fullmatch(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?:\+[A-Za-z0-9.-]+)?", version or "")
    if not match:
        return "unknown", None, "Missing, malformed, prerelease or vendor-suffixed version"
    parsed = tuple(int(x) for x in match.groups())
    if parsed[0] in EOL:
        return "unsupported", None, "Release line was end-of-life as of the embedded rule date"
    minimum = FIXED.get(parsed[0])
    if minimum is None:
        return "unknown", None, "Release line is not covered by this advisory rule set"
    fixed = ".".join(map(str, minimum))
    if parsed < minimum:
        return "vulnerable_by_version", fixed, "Below the upstream fixed version; vendor backports not verified"
    return "patched_by_version", fixed, "Meets this advisory's version cutoff; vendor patch and integrity not verified"


def finding(target, version=None, evidence="none", reason=None, **extra):
    status, fixed, explanation = classify(version)
    return dict(target=target, node_version=version, patch_status=status,
                fixed_version=fixed, evidence=evidence, reason=reason or explanation, **extra)


def embedded_version(data):
    if data[:4] not in MAGICS and data[:2] != b"MZ":
        return None, "Not a recognized executable binary; not executed"
    # shortcut: use a uniquely embedded Node download URL, not arbitrary semver strings.
    # Custom/vendor binaries without this marker need an explicit trusted --node probe.
    version = None
    for match in re.finditer(rb"node\.js/v(\d{1,4}\.\d{1,4}\.\d{1,4})(?![0-9A-Za-z.+-])", data):
        account()
        found = match.group(1).decode("ascii")
        if version is not None and found != version:
            return None, "No unique embedded Node version marker; not executed"
        version = found
    return (version, None) if version else (None, "No unique embedded Node version marker; not executed")


def inspect_file(path):
    target = str(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
                return finding(target, reason="Not a regular file, empty, or exceeds the 256 MiB read limit")
            account()
            data = stream.read(read_size(MAX_BYTES + 1))
            account(byte_count=len(data))
            if len(data) != info.st_size:
                return finding(target, reason="File size changed during inspection; incomplete")
            version, error = embedded_version(data)
        return finding(target, version, "embedded_version_string", error)
    except (OSError, ValueError) as exc:
        return finding(target, reason=type(exc).__name__ + ": file could not be read")


def scan_root(root):
    root = Path(root).expanduser().absolute()
    if not root.is_dir():
        return [finding(str(root), reason="Scan root is absent or is not a directory")], 0
    results = []
    entries = 0
    def failed(exc):
        results.append(finding(exc.filename or str(root), reason="Directory access failed (errno %s)" % exc.errno))
    try:
        for path, is_dir, linked in walk_entries(root, failed):
            if linked:
                results.append(finding(str(path), evidence="skipped_symlink",
                                       reason="Symlink skipped; target remains unverified. Do not execute scan discoveries."))
                if path.name in NODE_NAMES:
                    entries += 1
            elif not is_dir:
                entries += 1
                if path.name in NODE_NAMES:
                    results.append(inspect_file(path))
    except ScanLimit:
        pass  # The CLI adds the budget failure after preserving these findings.
    if not results:
        results.append(finding(str(root), reason="No named Node binary found; other names and inaccessible paths may be missed"))
    return results, entries


PROBE_OUTPUT_LIMIT = 4096


def local_probe(binary, timeout):
    resolved = shutil.which(binary) if not os.path.dirname(binary) else os.path.abspath(os.path.expanduser(binary))
    if not resolved:
        return finding(binary, reason="Executable was not found")
    if os.geteuid() == 0:
        return finding(resolved, reason="Executable probes are refused as root")
    proc = None
    try:
        # This is an authorized trusted-program query, not a sandbox.
        proc = subprocess.Popen([resolved, "--version"], cwd="/", env={"PATH": os.defpath},
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        deadline = time.monotonic() + timeout
        output = bytearray()
        total = 0
        with selectors.DefaultSelector() as selector:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                account()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return finding(resolved, reason="Version query timed out; not retried")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, min(4096, PROBE_OUTPUT_LIMIT - total + 1))
                    total += len(chunk)
                    if total > PROBE_OUTPUT_LIMIT:
                        return finding(resolved, reason="Version query exceeded the combined stdout/stderr limit")
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is proc.stdout:
                        output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return finding(resolved, reason="Version query timed out; not retried")
        code = proc.wait(timeout=remaining)
        text = output.decode("utf-8", errors="replace").strip()
        if code or len(text) > 128 or not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", text):
            return finding(resolved, evidence="explicit_executable_probe", reason="Version query failed or returned an unexpected banner")
        return finding(resolved, text, "explicit_executable_probe")
    except subprocess.TimeoutExpired:
        return finding(resolved, reason="Version query timed out; not retried")
    except OSError as exc:
        return finding(resolved, reason=type(exc).__name__ + ": version query could not run")
    finally:
        if proc is not None:
            # Also stop descendants that inherited pipes, even if the parent exited.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for stream in (proc.stdout, proc.stderr):
                stream.close()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass  # An uninterruptible kernel wait cannot be bounded by user-space cleanup.


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, path, timeout):
        self.path, self.timeout = path, timeout

    def json(self, endpoint):
        account()
        connection = UnixConnection(self.path, self.timeout)
        try:
            connection.request("GET", endpoint)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("Docker GET returned HTTP %s" % response.status)
            account()
            body = response.read(read_size(8 * 1024 * 1024 + 1))
            account(byte_count=len(body))
            if len(body) > 8 * 1024 * 1024:
                raise ValueError("Docker metadata exceeds the 8 MiB limit")
            return json.loads(body)
        finally:
            connection.close()

    def file(self, container, path, redirects=0):
        """Read a single archive member in memory. Never extract or execute it."""
        account()
        if redirects > 4:
            return None, "Container file symlink chain exceeds four links"
        connection = UnixConnection(self.path, self.timeout)
        link = None
        try:
            connection.request("GET", "/containers/" + container + "/archive?path=" + urllib.parse.quote(path, safe=""))
            response = connection.getresponse()
            if response.status == 404:
                return None, None
            if response.status != 200:
                return None, "Docker archive HTTP %s" % response.status
            with tarfile.open(fileobj=BoundedReader(response, MAX_BYTES + 1024 * 1024), mode="r|") as archive:
                for member in archive:
                    account(entries=1)
                    if member.isdir():
                        return None, "Expected a file; directory archive not traversed"
                    if member.issym() or member.islnk():
                        link = member.linkname
                        break
                    if member.isfile():
                        if not 0 < member.size <= MAX_BYTES:
                            return None, "Container file is empty or exceeds the 256 MiB read limit"
                        stream = archive.extractfile(member)
                        data = stream.read(member.size + 1)
                        if len(data) != member.size:
                            return None, "Truncated container file"
                        return data, None
            if link is None:
                return None, "Archive did not contain a regular file"
        finally:
            connection.close()
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), link))
        if not target.startswith("/") or target == "/":
            return None, "Invalid container file symlink target"
        return self.file(container, target, redirects + 1)


def inspect_container(client, container):
    cid = container["Id"]
    if not re.fullmatch(r"[a-f0-9]{12,64}", cid):
        raise ValueError("Invalid container identity")
    info = client.json("/containers/" + cid + "/json")
    target = info.get("Name", cid).lstrip("/")
    config = info.get("Config") or {}
    extra = dict(container_id=cid, state=info["State"]["Status"], image=config.get("Image"))
    errors = []
    binaries = []
    for path in BINARY_PATHS:
        try:
            data, error = client.file(cid, path)
            if error:
                errors.append(path + ": " + error)
            if data:
                version, reason = embedded_version(data)
                binaries.append(finding(target, version, "container_binary_embedded_string", reason, path=path))
        except ScanLimit:
            errors.append(path + ": scan budget exhausted")
            break
        except (OSError, ValueError, tarfile.TarError, http.client.HTTPException) as exc:
            errors.append(path + ": " + type(exc).__name__)
    if binaries:
        if errors:
            binaries.append(finding(target, reason="Some standard binary paths could not be read"))
        status, _ = summarize(binaries)
        row = dict(next(item for item in binaries if item["patch_status"] == status))
        row.update(extra, read_errors=errors, binary_observations=binaries)
        return row
    versions = set()
    for path in HEADER_PATHS:
        try:
            data, error = client.file(cid, path)
            if error:
                errors.append(path + ": " + error)
            if data:
                parts = [re.search(rb"#define\s+NODE_" + part + rb"_VERSION\s+(\d{1,4})\b", data)
                         for part in (b"MAJOR", b"MINOR", b"PATCH")]
                if all(parts):
                    versions.add(".".join(p.group(1).decode("ascii") for p in parts))
        except ScanLimit:
            errors.append(path + ": scan budget exhausted")
            break
        except (OSError, ValueError, tarfile.TarError, http.client.HTTPException) as exc:
            errors.append(path + ": " + type(exc).__name__)
    env_versions = {entry.split("=", 1)[1] for entry in (config.get("Env") or [])
                    if entry.startswith("NODE_VERSION=")}
    if versions:
        evidence = "container_header_metadata"
    else:
        versions, evidence = env_versions, "container_config_metadata"
    if len(versions) == 1:
        row = finding(target, versions.pop(), evidence, read_errors=errors, **extra)
        row["metadata_patch_status"] = row["patch_status"]
        row["patch_status"] = "unknown"
        row["reason"] = "Version is metadata only; installed runtime version is unverified"
        return row
    return finding(target, reason="No unique version in probed files or metadata; not evidence of no Node installation",
                   read_errors=errors, **extra)


def docker_scan(path, timeout):
    client = Docker(path, timeout)
    try:
        version = client.json("/version")
        if not isinstance(version, dict) or not version.get("Version"):
            raise ValueError("Unexpected Docker identity response")
        containers = client.json("/containers/json?all=true")
        if not isinstance(containers, list):
            raise ValueError("Unexpected container listing")
    except (OSError, ValueError, TypeError, http.client.HTTPException) as exc:
        return [finding(path, reason="Docker preflight failed: " + type(exc).__name__)]
    results = []
    try:
        for container in containers:
            account(entries=1)
            try:
                results.append(inspect_container(client, container))
            except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as exc:
                identity = container.get("Id", "unknown") if isinstance(container, dict) else "unknown"
                results.append(finding(str(identity), reason="Container read failed: " + type(exc).__name__))
    except ScanLimit:
        pass
    return results or [finding(path, reason="No containers returned; image contents were not scanned")]


def summarize(results):
    statuses = {r["patch_status"] for r in results}
    if "vulnerable_by_version" in statuses:
        return "vulnerable_by_version", 1
    if "unsupported" in statuses:
        return "unsupported", 1
    if "unknown" in statuses or not statuses:
        return "unknown", 3
    return "patched_by_version", 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    parser.add_argument("--node-version", action="append", default=[], metavar="VERSION", help="classify a supplied version without executing it")
    parser.add_argument("--allow-exec", action="store_true", help="acknowledge that --local/--node executes trusted code with your privileges; not a sandbox")
    parser.add_argument("--local", action="store_true", help="execute the trusted Node on PATH with --version")
    parser.add_argument("--node", action="append", default=[], metavar="PATH", help="explicitly execute a trusted Node path with --version")
    parser.add_argument("--scan", action="append", default=[], metavar="DIRECTORY", help="scan filenames and embedded strings; never execute discoveries")
    parser.add_argument("--docker", action="store_true", help="read local Docker metadata and standard binary paths; no exec or lifecycle calls")
    parser.add_argument("--docker-socket", help="explicit local Unix socket; no TCP/SSH endpoint support")
    parser.add_argument("--timeout", type=float, default=10, help="seconds per operation, greater than zero and at most 60")
    parser.add_argument("--max-seconds", type=float, default=60, help="overall scan deadline, greater than 0 and at most 600 seconds")
    parser.add_argument("--max-entries", type=int, default=100000, help="overall entry budget, 1 to 100000")
    parser.add_argument("--json", action="store_true", help="write one JSON report to stdout")
    args = parser.parse_args(argv)
    if not 0 < args.timeout <= 60:
        parser.error("--timeout must be greater than zero and at most 60")
    if args.docker_socket and not args.docker:
        parser.error("--docker-socket requires --docker")
    if args.docker_socket and "://" in args.docker_socket:
        parser.error("only a local Unix socket filesystem path is accepted")
    if not (args.node_version or args.local or args.node or args.scan or args.docker):
        parser.error("select --local, --node, --node-version, --scan or --docker")
    if not 0 < args.max_seconds <= 600 or not 1 <= args.max_entries <= 100000:
        parser.error("--max-seconds must be in (0, 600]; --max-entries must be in [1, 100000]")
    if bool(args.local or args.node) != args.allow_exec:
        parser.error("--local/--node requires --allow-exec; use static --scan for untrusted files")
    if any(not os.path.isabs(path) for path in args.node):
        parser.error("--node requires an absolute path to a trusted executable")
    if (args.local or args.node) and os.geteuid() == 0:
        parser.error("executable probes are refused as root")
    if not sys.flags.no_site or not sys.flags.isolated:
        parser.error("start this checker with a trusted Python and -I -S")
    results = [finding("supplied_version", value, "user_supplied") for value in args.node_version]
    file_entries = 0
    budget = ScanBudget(args.max_seconds, args.max_entries)
    with budget:
        for binary in (["node"] if args.local else []) + args.node:
            account(entries=1)
            results.append(local_probe(binary, args.timeout))
        for root in args.scan:
            account()
            rows, entries = scan_root(root)
            file_entries += entries
            results.extend(rows)
        if args.docker:
            account()
            desktop = Path.home() / ".docker/run/docker.sock"
            path = args.docker_socket or str(desktop if desktop.exists() else Path("/var/run/docker.sock"))
            results.extend(docker_scan(path, args.timeout))
    if budget.limit:
        results.append(finding("selected_scope", evidence="resource_limit", reason=budget.limit))
    status, code = summarize(results)
    report = dict(tool_version=TOOL_VERSION, rules_as_of=RULES_AS_OF, advisory=ADVISORY,
                  checked_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  patch_status=status, exit_code=code, compromise_status="not_assessed",
                  file_entries=file_entries, results=results,
                  resource_limits=dict(max_seconds=args.max_seconds, max_entries=args.max_entries,
                                       max_read_bytes=budget.byte_limit, entries=budget.entries,
                                       bytes_read=budget.bytes_read, limit_reached=budget.limit),
                  limitations=["Only the specified October 2026 advisory is assessed; not a latest-patch or all-CVE scan.",
                               "Version strings, headers and config metadata do not verify vendor backports or binary integrity.",
                               "Docker reads standard paths only; custom paths, other images, nested daemons and live process memory are not covered.",
                               "Unknown or skipped paths remain unverified. This report cannot establish absence of compromise."])
    if args.json:
        print(json.dumps(report, ensure_ascii=True, indent=2))
    else:
        print("%s (exit %s); compromise: NOT ASSESSED" % (status.upper(), code))
        for result in results:
            # ascii prevents untrusted filenames or metadata from injecting terminal control sequences.
            print("%s %s %s -- %s" % (result["patch_status"].upper(), ascii(result["target"]),
                                        ascii(result["node_version"]), ascii(result["reason"])))
        print("Rules: %s; %s" % (RULES_AS_OF, ADVISORY))
    return code


if __name__ == "__main__":
    sys.exit(main())
