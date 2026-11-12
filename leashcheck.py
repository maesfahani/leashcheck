#!/usr/bin/env python3
"""leashcheck - how much damage could an AI agent do from where it is running?

Run this *inside* the environment your coding agent runs in (ask the agent to
run it, or run it in the same sandbox/container). It performs harmless probes
and prints a scorecard.

Safety rules every probe follows:
  * secrets are never printed, stored, or sent anywhere (only names/paths/counts)
  * read checks open a file and read one byte, which is discarded
  * write checks create an empty, uniquely named canary file and delete it at
    once, or open an existing file for append without writing to it
  * network checks only open a TCP connection; no data about you is sent

Single file, standard library only, Python 3.8+.
"""
from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import platform
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

VERSION = "0.1.0"
WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1}
SEV_ORDER = ["critical", "high", "medium", "low"]


@dataclass
class Result:
    id: str
    category: str
    title: str
    severity: str
    status: str  # "exposed" | "protected" | "na"
    detail: str = ""
    fix: str = ""


@dataclass
class Ctx:
    homes: list
    project: str
    network: bool = True
    timeout: float = 3.0


# --------------------------------------------------------------------------
# low-level harmless checks
# --------------------------------------------------------------------------

def can_read(path):
    """True if readable, False if blocked, None if there is nothing to read."""
    try:
        if os.path.isdir(path):
            return True if os.listdir(path) else None
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def can_open_for_write(path):
    """Open an existing file for append and close it. Nothing is written."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    except OSError:
        return False
    os.close(fd)
    return True


def can_create_in(directory):
    """Create and immediately delete an empty canary file. None if no such dir."""
    if not os.path.isdir(directory):
        return None
    name = os.path.join(directory, ".leashcheck-canary-%s" % secrets.token_hex(6))
    try:
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return False
    os.close(fd)
    try:
        os.unlink(name)
    except OSError:
        pass
    return True


def tcp_open(host, port, timeout):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def unix_connect(path, timeout=1.0):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except (OSError, AttributeError):
        return None
    try:
        s.settimeout(timeout)
        s.connect(path)
        return s
    except OSError:
        s.close()
        return None


def ssh_agent_keys(path):
    """Number of keys an SSH agent socket offers, or None if unreachable."""
    s = unix_connect(path)
    if not s:
        return None
    try:
        s.sendall(struct.pack(">IB", 1, 11))  # SSH_AGENTC_REQUEST_IDENTITIES
        reply = s.recv(9)
        if len(reply) >= 9 and reply[4] == 12:
            return struct.unpack(">I", reply[5:9])[0]
    except OSError:
        pass
    finally:
        s.close()
    return None


def udp_dns_works(timeout):
    """Send one ordinary DNS query for example.com straight to a public resolver."""
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(query, ("1.1.1.1", 53))
        return s.recvfrom(512)[0][:2] == query[:2]
    except OSError:
        return False
    finally:
        s.close()


def pretty(path, homes):
    for home in homes:
        if path == home or path.startswith(home + os.sep):
            return "~" + path[len(home):]
    return path


def proc_status():
    fields = {}
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
    except OSError:
        pass
    return fields


# --------------------------------------------------------------------------
# probes: files the agent can read
# --------------------------------------------------------------------------

READ_TARGETS = [
    ("read.ssh_keys", "SSH private keys", "critical",
     [".ssh/id_*", ".ssh/*.pem", ".ssh/*.key"],
     "Do not mount ~/.ssh into the agent's environment. Use a short-lived deploy key or token scoped to one repo."),
    ("read.cloud", "Cloud provider credentials", "critical",
     [".aws/credentials", ".aws/sso/cache", ".config/gcloud/application_default_credentials.json",
      ".config/gcloud/credentials.db", ".azure/msal_token_cache.json", ".azure/accessTokens.json",
      ".config/doctl/config.yaml", ".oci/config"],
     "Keep cloud credential directories outside the sandbox. If the agent needs cloud access, issue short-lived, least-privilege credentials."),
    ("read.kube", "Kubernetes config", "critical", [".kube/config"],
     "Keep ~/.kube out of the sandbox, or provide a kubeconfig bound to a read-only, single-namespace role."),
    ("read.git_creds", "Git / GitHub credentials", "critical",
     [".git-credentials", ".config/gh/hosts.yml", ".netrc", ".config/glab-cli/config.yml"],
     "Hide these files from the agent. Give it a fine-grained token limited to the one repository it works on."),
    ("read.registries", "Package registry and Docker tokens", "high",
     [".npmrc", ".pypirc", ".docker/config.json", ".cargo/credentials.toml", ".gem/credentials"],
     "A leaked publish token enables supply-chain attacks. Keep these out of the sandbox; use read-only registry tokens."),
    ("read.gpg", "GPG private keys / password store", "high",
     [".gnupg/private-keys-v1.d", ".password-store"],
     "Do not expose ~/.gnupg or ~/.password-store to the agent."),
    ("read.browser", "Browser profiles (cookies, sessions)", "high",
     [".mozilla/firefox", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
      "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
      "Library/Cookies"],
     "Browser profiles hold live login sessions. Restrict the agent's filesystem view to the project directory."),
    ("read.history", "Shell history", "medium",
     [".bash_history", ".zsh_history", ".local/share/fish/fish_history", ".python_history", ".psql_history"],
     "History files often contain pasted secrets. Restrict the agent's filesystem view to the project directory."),
]


def probe_reads(ctx):
    out = []
    for pid, title, sev, patterns, fix in READ_TARGETS:
        readable, blocked = [], []
        for home in ctx.homes:
            for pat in patterns:
                for path in glob.glob(os.path.join(home, pat)):
                    if path.endswith(".pub"):
                        continue
                    state = can_read(path)
                    if state is True:
                        readable.append(path)
                    elif state is False:
                        blocked.append(path)
        if readable:
            shown = ", ".join(pretty(p, ctx.homes) for p in readable[:3])
            more = " (+%d more)" % (len(readable) - 3) if len(readable) > 3 else ""
            out.append(Result(pid, "Files it can read", title, sev, "exposed",
                              "readable: %s%s" % (shown, more), fix))
        elif blocked:
            out.append(Result(pid, "Files it can read", title, sev, "protected",
                              "present but not readable"))
        else:
            out.append(Result(pid, "Files it can read", title, sev, "na", "not present or not visible"))

    # project .env files
    envs = [p for p in glob.glob(os.path.join(ctx.project, ".env*"))
            if os.path.isfile(p) and not re.search(r"\.(example|sample|template|dist)$", p)]
    readable = [p for p in envs if can_read(p)]
    if readable:
        out.append(Result("read.dotenv", "Files it can read", "Project .env files", "medium", "exposed",
                          "readable: %s" % ", ".join(os.path.basename(p) for p in readable[:4]),
                          "Keep only development secrets in .env. Never place production credentials where an agent works."))
    else:
        out.append(Result("read.dotenv", "Files it can read", "Project .env files", "medium",
                          "protected" if envs else "na", "not readable" if envs else "none found"))

    # other projects next to this one
    parent = os.path.dirname(ctx.project.rstrip(os.sep)) or os.sep
    try:
        others = [e for e in os.listdir(parent) if e != os.path.basename(ctx.project.rstrip(os.sep))]
    except OSError:
        others = None
    if others:
        out.append(Result("read.siblings", "Files it can read", "Directories outside the project", "medium", "exposed",
                          "%d other entries visible in %s" % (len(others), pretty(parent, ctx.homes)),
                          "Mount only the project directory (ideally a copy or git worktree) into the sandbox."))
    else:
        out.append(Result("read.siblings", "Files it can read", "Directories outside the project", "medium",
                          "protected", "parent directory is empty or not listable"))
    return out


# --------------------------------------------------------------------------
# probes: places the agent can write / delete
# --------------------------------------------------------------------------

STARTUP_FILES = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
                 ".config/fish/config.fish", ".gitconfig"]


def probe_writes(ctx):
    cat = "Files it can change or delete"
    out = []

    states = [can_create_in(h) for h in ctx.homes]
    if any(s is True for s in states):
        out.append(Result("write.home", cat, "Home directory", "high", "exposed",
                          "created and deleted a canary file in ~",
                          "Make everything outside the project read-only or invisible. A runaway `rm -rf` then stops at the project."))
    else:
        out.append(Result("write.home", cat, "Home directory", "high",
                          "na" if all(s is None for s in states) else "protected", "not writable"))

    writable = [f for h in ctx.homes for f in STARTUP_FILES if can_open_for_write(os.path.join(h, f))]
    present = [f for h in ctx.homes for f in STARTUP_FILES if os.path.exists(os.path.join(h, f))]
    if writable:
        out.append(Result("write.startup", cat, "Shell startup files and git config", "high", "exposed",
                          "writable: %s" % ", ".join("~/" + f for f in sorted(set(writable))[:4]),
                          "Writable startup files let a command planted now run later, outside the sandbox. Make them read-only to the agent."))
    else:
        out.append(Result("write.startup", cat, "Shell startup files and git config", "high",
                          "protected" if present else "na", "not writable" if present else "not present"))

    states = [can_create_in(os.path.join(h, ".ssh")) for h in ctx.homes]
    if any(s is True for s in states):
        out.append(Result("write.ssh", cat, "~/.ssh (authorized_keys, config)", "high", "exposed",
                          "created and deleted a canary file in ~/.ssh",
                          "Write access here allows adding a login key or redirecting SSH hosts. Keep ~/.ssh out of the sandbox."))
    else:
        out.append(Result("write.ssh", cat, "~/.ssh (authorized_keys, config)", "high",
                          "na" if all(s is None for s in states) else "protected", "not writable"))

    parent = os.path.dirname(ctx.project.rstrip(os.sep)) or os.sep
    state = can_create_in(parent)
    if state:
        out.append(Result("write.parent", cat, "Parent of the project directory", "medium", "exposed",
                          "created and deleted a canary file in %s" % pretty(parent, ctx.homes),
                          "Limit write access to the project directory itself."))
    else:
        out.append(Result("write.parent", cat, "Parent of the project directory", "medium",
                          "na" if state is None else "protected", "not writable"))

    sysdirs = [d for d in ("/etc", "/usr/bin", "/usr/local/bin") if can_create_in(d)]
    if sysdirs:
        boxed = in_container()  # a container's own /etc is disposable
        out.append(Result("write.system", cat, "System directories", "low" if boxed else "critical", "exposed",
                          "writable: %s%s" % (", ".join(sysdirs), " (container filesystem)" if boxed else ""),
                          "The agent can alter the operating system. Run it as an unprivileged user, in a container or VM that is disposable."))
    else:
        out.append(Result("write.system", cat, "System directories", "critical", "protected", "not writable"))
    return out


# --------------------------------------------------------------------------
# probes: secrets in the process environment
# --------------------------------------------------------------------------

SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)


def probe_env(ctx):
    cat = "Secrets within reach"
    out = []
    names = sorted(k for k, v in os.environ.items() if v and SECRET_NAME.search(k))
    if names:
        more = " (+%d more)" % (len(names) - 5) if len(names) > 5 else ""
        out.append(Result("env.secrets", cat, "Secret-looking environment variables", "high", "exposed",
                          "names only: %s%s" % (", ".join(names[:5]), more),
                          "Start the agent with a clean environment (e.g. `env -i`, or an explicit allowlist). Pass only what the task needs."))
    else:
        out.append(Result("env.secrets", cat, "Secret-looking environment variables", "high", "protected", "none found"))

    env_sock = os.environ.get("SSH_AUTH_SOCK")
    run = "/run/user/%d" % (os.getuid() if hasattr(os, "getuid") else 0)
    candidates = ([env_sock] if env_sock else []) + [run + p for p in (
        "/keyring/ssh", "/gcr/ssh", "/openssh_agent", "/ssh-agent.socket")] + glob.glob("/tmp/ssh-*/agent.*")
    found = None
    for path in dict.fromkeys(candidates):
        count = ssh_agent_keys(path)
        if count:
            found = (path, count)
            break
    if found:
        via = "SSH_AUTH_SOCK" if found[0] == env_sock else "a well-known socket path, although SSH_AUTH_SOCK is not set"
        out.append(Result("env.ssh_agent", cat, "SSH agent", "high", "exposed",
                          "%d key(s) usable via %s, without reading any key file" % (found[1], via),
                          "Unsetting SSH_AUTH_SOCK is not enough: the socket itself must be unreachable. "
                          "Give the agent its own /run and /tmp (a mount namespace or container)."))
    else:
        out.append(Result("env.ssh_agent", cat, "SSH agent", "high", "protected" if env_sock else "na",
                          "no agent socket reachable or no keys loaded"))

    if os.path.isdir("/proc"):
        me, readable = os.getpid(), 0
        try:
            entries = os.listdir("/proc")
        except OSError:
            entries = []
        for entry in entries:
            if entry.isdigit() and int(entry) != me:
                try:
                    os.close(os.open("/proc/%s/environ" % entry, os.O_RDONLY))
                    readable += 1
                except OSError:
                    pass
        if readable:
            out.append(Result("env.other_procs", cat, "Environment of other processes", "high", "exposed",
                              "can open the environment of %d other process(es)" % readable,
                              "Use a separate PID namespace (containers do this by default) or a separate OS user for the agent."))
        else:
            out.append(Result("env.other_procs", cat, "Environment of other processes", "high", "protected",
                              "no other process environment is readable"))
    return out


# --------------------------------------------------------------------------
# probes: network
# --------------------------------------------------------------------------

def proxy_connect(host, port, timeout):
    """Ask the configured HTTP proxy to tunnel to host:port. None if no usable proxy."""
    raw = next((os.environ[k] for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                                        "ALL_PROXY", "all_proxy") if os.environ.get(k)), None)
    if not raw:
        return None
    url = urlsplit(raw if "://" in raw else "http://" + raw)
    if url.scheme != "http" or not url.hostname:
        return None
    request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)
    if url.username:
        token = base64.b64encode(("%s:%s" % (url.username, url.password or "")).encode()).decode()
        request += "Proxy-Authorization: Basic %s\r\n" % token
    try:
        s = socket.create_connection((url.hostname, url.port or 80), timeout=timeout)
        s.settimeout(timeout)
        s.sendall((request + "\r\n").encode())
        status = s.recv(64).split(b"\r\n")[0]
        s.close()
        return b" 200" in status
    except OSError:
        return False


LOCAL_PORTS = {5432: "postgres", 3306: "mysql", 6379: "redis", 27017: "mongodb",
               9200: "elasticsearch", 2375: "docker-tcp"}


def probe_network(ctx):
    cat = "Network"
    if not ctx.network:
        return [Result("net.skipped", cat, "Network probes", "low", "na", "skipped (--no-network)")]
    out = []

    how = None
    if tcp_open("example.com", 443, ctx.timeout):
        how = "direct connection to example.com:443"
    elif tcp_open("1.1.1.1", 443, ctx.timeout):
        how = "direct connection to 1.1.1.1:443 (DNS blocked, raw IP allowed)"
    elif proxy_connect("example.com", 443, ctx.timeout):
        how = "the configured proxy tunnels to example.com:443"
    if how:
        out.append(Result("net.outbound", cat, "Outbound access to an arbitrary host", "high", "exposed", how,
                          "Deny outbound traffic by default and allowlist the few hosts needed (package registry, model API). "
                          "Open egress is how stolen data leaves and how malicious scripts arrive."))
    else:
        out.append(Result("net.outbound", cat, "Outbound access to an arbitrary host", "high", "protected",
                          "example.com unreachable directly and through any proxy"))

    try:
        socket.getaddrinfo("example.com", 443)
        leak = "example.com resolves; data can leave inside DNS queries even when connections are blocked"
    except OSError:
        leak = ("the system resolver fails, but a UDP query sent straight to 1.1.1.1:53 is answered"
                if udp_dns_works(min(ctx.timeout, 2.0)) else None)
    if leak:
        out.append(Result("net.dns", cat, "DNS / UDP egress", "medium", "exposed", leak,
                          "Resolve names only through a filtering proxy or resolver, or give the sandbox no resolver at all."))
    else:
        out.append(Result("net.dns", cat, "DNS / UDP egress", "medium", "protected",
                          "example.com does not resolve and direct UDP to a public resolver gets no answer"))

    if tcp_open("169.254.169.254", 80, min(ctx.timeout, 1.0)):
        out.append(Result("net.metadata", cat, "Cloud metadata service", "critical", "exposed",
                          "169.254.169.254:80 accepts connections",
                          "The metadata service hands out the machine's cloud role credentials. Block 169.254.169.254 for the agent."))
    else:
        out.append(Result("net.metadata", cat, "Cloud metadata service", "critical", "protected", "not reachable"))

    found = ["%s (%d)" % (name, port) for port, name in LOCAL_PORTS.items() if tcp_open("127.0.0.1", port, 0.3)]
    if found:
        out.append(Result("net.local", cat, "Local services on this machine", "medium", "exposed",
                          "listening: %s" % ", ".join(found),
                          "Local databases often accept connections without a password. Give the agent its own network namespace."))
    else:
        out.append(Result("net.local", cat, "Local services on this machine", "medium", "protected",
                          "no common database ports open on 127.0.0.1"))
    return out


# --------------------------------------------------------------------------
# probes: privilege
# --------------------------------------------------------------------------

def probe_privilege(ctx):
    cat = "Privilege"
    out = []
    uid = os.getuid() if hasattr(os, "getuid") else -1

    if uid == 0:
        # root inside a container is confined by namespaces; still an escape amplifier
        out.append(Result("priv.root", cat, "Running as root", "medium" if in_container() else "high", "exposed",
                          "uid 0" + (" (inside a container)" if in_container() else ""),
                          "Run the agent as an unprivileged user, also inside containers (`USER` in the Dockerfile, or `--user`)."))
    else:
        out.append(Result("priv.root", cat, "Running as root", "high", "protected", "uid %d" % uid))

    if uid == 0 or not shutil.which("sudo"):
        out.append(Result("priv.sudo", cat, "Passwordless sudo", "critical", "na",
                          "already root" if uid == 0 else "sudo not installed"))
    else:
        try:
            ok = subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            out.append(Result("priv.sudo", cat, "Passwordless sudo", "critical", "exposed",
                              "`sudo -n true` succeeded",
                              "The agent can become root without asking. Remove NOPASSWD for this user, or run the agent as a user without sudo rights."))
        else:
            out.append(Result("priv.sudo", cat, "Passwordless sudo", "critical", "protected", "sudo needs a password"))

    candidates = ["/var/run/docker.sock", "/run/docker.sock", "/var/snap/lxd/common/lxd/unix.socket",
                  "/var/lib/lxd/unix.socket", "/var/lib/incus/unix.socket"]
    candidates += [os.path.join(h, ".docker/run/docker.sock") for h in ctx.homes]
    if os.environ.get("XDG_RUNTIME_DIR"):
        candidates += [os.path.join(os.environ["XDG_RUNTIME_DIR"], p) for p in ("docker.sock", "podman/podman.sock")]
    if os.environ.get("DOCKER_HOST", "").startswith("unix://"):
        candidates.append(os.environ["DOCKER_HOST"][7:])
    open_socks = []
    for path in dict.fromkeys(candidates):
        s = unix_connect(path)
        if s:
            s.close()
            open_socks.append(path)
    if open_socks:
        out.append(Result("priv.docker", cat, "Container runtime socket", "critical", "exposed",
                          "can connect to %s" % ", ".join(open_socks),
                          "Access to a container runtime socket equals root on the host (it can mount / into a new container). "
                          "Never mount the socket into an agent sandbox; remove the agent's user from the docker/lxd group."))
    else:
        out.append(Result("priv.docker", cat, "Container runtime socket", "critical", "protected",
                          "no Docker, Podman or LXD socket reachable"))

    buses = ["/run/user/%d/bus" % uid]
    match = re.search(r"unix:path=([^,;]+)", os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""))
    if match:
        buses.insert(0, match.group(1))
    reachable = None
    for path in dict.fromkeys(buses):
        s = unix_connect(path)
        if s:
            s.close()
            reachable = path
            break
    if reachable:
        out.append(Result("priv.session_bus", cat, "User session bus (systemd --user, D-Bus)", "high", "exposed",
                          "can connect to %s; `systemd-run --user` can start processes outside a sandbox" % reachable,
                          "A filesystem-only sandbox does not block this socket. Give the agent its own /run "
                          "(mount namespace or container) so the session bus is not reachable."))
    else:
        out.append(Result("priv.session_bus", cat, "User session bus (systemd --user, D-Bus)", "high", "protected",
                          "session bus not reachable"))

    cap_eff = proc_status().get("CapEff")
    if cap_eff is None:
        out.append(Result("priv.caps", cat, "CAP_SYS_ADMIN capability", "high", "na", "not Linux"))
    elif int(cap_eff, 16) & (1 << 21):
        out.append(Result("priv.caps", cat, "CAP_SYS_ADMIN capability", "high", "exposed",
                          "CapEff=%s (less severe if confined to a user namespace)" % cap_eff,
                          "Drop capabilities (`--cap-drop=ALL`) and never use `--privileged`."))
    else:
        out.append(Result("priv.caps", cat, "CAP_SYS_ADMIN capability", "high", "protected", "not held"))
    return out


# --------------------------------------------------------------------------
# environment summary, scoring, output
# --------------------------------------------------------------------------

def in_container():
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv") or os.environ.get("container"):
        return True
    try:
        with open("/proc/1/cgroup") as fh:
            return bool(re.search(r"docker|kubepods|containerd|lxc|podman", fh.read()))
    except OSError:
        return False


def environment(ctx):
    status = proc_status()
    seccomp = {"0": "off", "1": "strict", "2": "filter"}.get(status.get("Seccomp", ""), "unknown")
    try:
        import getpass
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return {
        "user": user,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "os": platform.system().lower(),
        "container": in_container(),
        "seccomp": seccomp,
        "no_new_privs": status.get("NoNewPrivs") == "1",
        "project": ctx.project,
    }


def run_all(ctx):
    results = []
    for probe in (probe_reads, probe_writes, probe_env, probe_network, probe_privilege):
        try:
            results.extend(probe(ctx))
        except Exception as exc:  # a broken probe must not hide the others
            results.append(Result(probe.__name__, "Errors", probe.__name__, "low", "na", "probe failed: %r" % exc))
    return results


def score(results):
    exposed = [r for r in results if r.status == "exposed"]
    points = max(0, 100 - sum(WEIGHT[r.severity] for r in exposed))
    grade = "A" if points >= 90 else "B" if points >= 75 else "C" if points >= 55 else "D" if points >= 35 else "F"
    if any(r.severity == "critical" for r in exposed) and grade in "ABC":
        grade = "D"  # one critical exposure is enough to lose everything
    return points, grade


def render(results, env, color):
    def paint(code, text):
        return "\033[%sm%s\033[0m" % (code, text) if color else text

    utf = (sys.stdout.encoding or "").lower().startswith("utf")
    bad, good, skip = ("✗", "✓", "–") if utf else ("x", "ok", "-")
    sev_color = {"critical": "1;31", "high": "31", "medium": "33", "low": "36"}
    lines = [paint("1", "leashcheck %s" % VERSION) + "  what could an AI agent do from here?", ""]
    lines.append("user %s (uid %s) | %s | container: %s | seccomp: %s | no_new_privs: %s" % (
        env["user"], env["uid"], env["os"], "yes" if env["container"] else "no", env["seccomp"],
        "yes" if env["no_new_privs"] else "no"))
    lines.append("project %s" % env["project"])

    for cat in dict.fromkeys(r.category for r in results):
        lines += ["", paint("1", cat.upper())]
        for r in (r for r in results if r.category == cat):
            if r.status == "exposed":
                mark = paint(sev_color[r.severity], "%s %-8s" % (bad, r.severity.upper()))
            elif r.status == "protected":
                mark = paint("32", "%s %-8s" % (good, "ok"))
            else:
                mark = paint("2", "%s %-8s" % (skip, "n/a"))
            lines.append("  %s  %-38s %s" % (mark, r.title, paint("2", r.detail)))

    exposed = [r for r in results if r.status == "exposed"]
    points, grade = score(results)
    counts = ", ".join("%d %s" % (n, s) for s in SEV_ORDER
                       for n in [sum(1 for r in exposed if r.severity == s)] if n)
    lines += ["", paint("1", "Score %d/100, grade %s" % (points, grade)) + "   %d exposed%s, %d protected, %d n/a" % (
        len(exposed), " (%s)" % counts if counts else "",
        sum(1 for r in results if r.status == "protected"), sum(1 for r in results if r.status == "na"))]

    if exposed:
        lines += ["", paint("1", "HOW TO FIX, most severe first")]
        for r in sorted(exposed, key=lambda r: SEV_ORDER.index(r.severity)):
            lines.append("  %s %s: %s" % (paint(sev_color[r.severity], "[%s]" % r.severity), r.title, r.fix))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="leashcheck", description=__doc__.split("\n\n")[0])
    ap.add_argument("--project", default=os.getcwd(), help="project directory the agent works in (default: cwd)")
    ap.add_argument("--home", help="home directory to inspect (default: detected)")
    ap.add_argument("--no-network", action="store_true", help="skip all network probes")
    ap.add_argument("--timeout", type=float, default=3.0, help="network timeout in seconds (default: 3)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", choices=SEV_ORDER, help="exit 1 if anything at this severity or worse is exposed")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)

    if args.home:
        homes = [os.path.abspath(args.home)]
    else:
        homes = [os.path.expanduser("~")]
        try:
            import pwd
            homes.append(pwd.getpwuid(os.getuid()).pw_dir)
        except Exception:
            pass
        homes = list(dict.fromkeys(os.path.abspath(h) for h in homes if h))
    ctx = Ctx(homes=homes, project=os.path.abspath(args.project), network=not args.no_network, timeout=args.timeout)

    results = run_all(ctx)
    env = environment(ctx)
    if args.json:
        points, grade = score(results)
        print(json.dumps({"version": VERSION, "environment": env, "score": points, "grade": grade,
                          "results": [asdict(r) for r in results]}, indent=2))
    else:
        print(render(results, env, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR")))

    if args.fail_on:
        limit = SEV_ORDER.index(args.fail_on)
        if any(r.status == "exposed" and SEV_ORDER.index(r.severity) <= limit for r in results):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
