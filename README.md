# leashcheck

**How much damage could an AI coding agent do from where it is running?**

`leashcheck` runs a set of harmless probes from inside your agent's environment
and prints a scorecard: which secrets it can read, which files it can change or
delete, where it can send data, and whether it can become root.

It works with any agent (Claude Code, Codex, Gemini CLI, Cursor, your own),
because it does not integrate with the agent. It only measures the environment.

## Use

One file, Python 3.8+, no dependencies.

```sh
python3 leashcheck.py
```

Run it **the way the agent would run it**: ask the agent to execute the command,
or run it inside the same container or sandbox. Running it in your normal
terminal shows your unsandboxed baseline.

| Option | Effect |
|---|---|
| `--project DIR` | project directory the agent works in (default: current directory) |
| `--no-network` | skip all network probes |
| `--json` | machine-readable output |
| `--fail-on high` | exit 1 if anything of that severity or worse is exposed (for CI) |

## What it checks

| Area | Probes |
|---|---|
| Files it can read | SSH keys, cloud credentials, kubeconfig, git/GitHub tokens, registry tokens, GPG keys, browser profiles, shell history, project `.env`, directories outside the project |
| Files it can change | home directory, shell startup files, `~/.ssh`, the project's parent, system directories |
| Secrets within reach | secret-looking environment variables, SSH agent socket, environment of other processes |
| Network | outbound access to an arbitrary host (direct or through a proxy), DNS and UDP egress, cloud metadata service, local database ports |
| Privilege | root, passwordless sudo, Docker/Podman/LXD socket, user session bus, `CAP_SYS_ADMIN` |

## Is it safe to run?

Yes, and the whole tool is one readable file so you can check.

- Secrets are never printed, stored, or sent. Output contains names, paths and counts only.
- Read checks open a file and read one byte, which is discarded.
- Write checks create an empty file named `.leashcheck-canary-<random>` and delete it at once,
  or open an existing file for append without writing.
- Network checks open a TCP connection to `example.com`, `1.1.1.1`, `169.254.169.254`
  and a few localhost ports, and may send one DNS query for `example.com` to `1.1.1.1`.
  Nothing about you is transmitted.
- Socket checks (SSH agent, Docker, session bus) connect and disconnect. The SSH agent is asked
  only how many keys it holds.
- `sudo -n true` is run once; on some systems a failed attempt is written to the auth log.

## Scoring

Starts at 100. Each exposure subtracts: critical 25, high 10, medium 4, low 1.
Any critical exposure caps the grade at D.

Inside a container, "running as root" counts as medium and "system directories
writable" as low, because they concern the container's own disposable filesystem.

## Tests

```sh
python3 -m unittest
```
