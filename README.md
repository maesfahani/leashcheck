# leashcheck

**Is your AI coding agent on a leash? Find out what it can reach on your machine.**

AI coding agents run shell commands. Whatever the agent's process can read, change or send,
a wrong command, a bad dependency or a prompt injection can read, change or send too.

This repository has two tools:

| Tool | What it does |
|---|---|
| **`leashcheck`** | Measures the problem. Runs harmless probes from inside the agent's environment and gives you a scorecard. |
| **[`leash`](#leash-run-claude-code-safely)** | Fixes it. Starts Claude Code in a hardened container with your project and the internet, and nothing else from your machine. Experimental. |

```sh
pipx run leashcheck        # measure: what can the agent reach right now?
cd ~/my-project && leash   # fix: run Claude Code on a leash
```

```text
leashcheck  what could an AI agent do from here?

FILES IT CAN READ
  ✗ CRITICAL  SSH private keys                       readable: ~/.ssh/id_ed25519, ~/.ssh/id_rsa
  ✗ CRITICAL  Git / GitHub credentials               readable: ~/.git-credentials
  ✗ HIGH      Browser profiles (cookies, sessions)   readable: ~/.mozilla/firefox, ~/.config/google-chrome
FILES IT CAN CHANGE OR DELETE
  ✗ HIGH      Home directory                         created and deleted a canary file in ~
  ✗ HIGH      Shell startup files and git config     writable: ~/.bashrc, ~/.gitconfig, ~/.profile
SECRETS WITHIN REACH
  ✗ HIGH      SSH agent                              3 key(s) usable, without reading any key file
NETWORK
  ✗ HIGH      Outbound access to an arbitrary host   direct connection to example.com:443
PRIVILEGE
  ✓ ok        Passwordless sudo                      sudo needs a password
  ...
Score 0/100, grade F   15 exposed (2 critical, 9 high, 4 medium)
```

*Shortened example of the output on an ordinary developer laptop with no sandbox.*

## Why it matters: the same machine, eight setups

We ran leashcheck on one Ubuntu machine under eight configurations. Same machine, same user,
same secrets on disk. Only the isolation changed.

| Setup | Score | What the agent could still reach |
|---|---|---|
| Docker, hardened, no network | **96 / A** | Nothing found |
| Docker, hardened, with network | **82 / B** | Any host on the internet, DNS |
| Landlock sandbox: files + TCP blocked, clean environment | **76 / B** | SSH agent, user session bus, UDP |
| Docker, default flags | **53 / D** | Internet, DNS, root inside the container |
| Landlock sandbox: files only | **52 / D** | The above, plus local databases and environment variables |
| No sandbox | **0 / F** | SSH keys, git credentials, browser sessions, the whole home directory, 15 exposures in all |
| No sandbox, clean environment | **0 / F** | Nearly the same: 14 exposures |
| Docker, home directory and Docker socket mounted | **0 / F** | Everything above, plus root on the host |

What this showed:

- **No sandbox means everything.** The default way most people run agents scored zero: SSH keys,
  saved git credentials and logged-in browser sessions were all readable, and the home directory writable.
- **A container is only as safe as its flags.** The same Docker scored 96 when hardened and 0 when
  started with the home directory and Docker socket mounted. That last setup was worse than no
  sandbox, because the Docker socket gives root on the host.
- **Filesystem sandboxes leak through sockets.** A path-based sandbox hid every file, yet the agent
  could still use the SSH agent and talk to `systemd --user`, which can start processes outside the sandbox.
- **Blocking TCP is not blocking the network.** With all TCP denied, a DNS query over UDP still got out.
- **Hiding environment variables alone changes almost nothing.**

Full method, per-probe table and limits: [study/REPORT.md](study/REPORT.md).
This is one machine and one run; run it on yours.

### The setup that scored 96

```sh
docker run --rm -v "$PWD":/w -w /w \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  --network none --read-only --tmpfs /tmp IMAGE COMMAND
```

Remove `--network none` if the agent needs the internet (score 82), or better, route it through
an allowlist proxy.

## leash: run Claude Code safely

`leash` is a one-word launcher that starts Claude Code inside a hardened container like the one
above, with the internet left on. Linux with Docker. It is experimental and has had little testing.

```sh
git clone https://github.com/maesfahani/leashcheck
ln -s "$PWD/leashcheck/leash/leash" ~/.local/bin/leash

cd ~/my-project
leash          # Claude Code, sandboxed; extra arguments go to claude
leash audit    # run leashcheck inside the same sandbox
leash shell    # a shell inside the same sandbox
```

| The agent gets | The agent does not get |
|---|---|
| The current directory, read-write | Your home directory: SSH keys, git credentials, browser profiles, history |
| The internet | Your SSH agent, the Docker socket, the session bus |
| A private home directory that keeps its Claude login | Root or any Linux capability |
| Your git name and email for commits | The host and local network (firewalled), other processes |
| | Write access to `.git/hooks` and `.git/config` |

Risk that remains: the agent can change or delete the project, can send anything it reads out to
the internet, and a container is weaker than a virtual machine against kernel exploits.
Details: [leash/README.md](leash/README.md).

## Use

Run it **the way the agent would run it**. Running it in your own terminal measures you, not the agent.

- **Ask the agent:** "run `pipx run leashcheck` and show me the full output".
- **Inside a container or sandbox:** run it as the command, as in the Docker example above.
- **Without installing:** it is one file with no dependencies. Copy `leashcheck.py` and run `python3 leashcheck.py`.

| Option | Effect |
|---|---|
| `--project DIR` | project directory the agent works in (default: current directory) |
| `--no-network` | skip all network probes |
| `--json` | machine-readable output |
| `--fail-on high` | exit 1 if anything of that severity or worse is exposed (for CI) |

Works with any agent (Claude Code, Codex, Gemini CLI, Cursor, your own), because it does not
integrate with the agent. It measures the environment. Python 3.8+, Linux; macOS is untested.

## What it checks

| Area | Probes |
|---|---|
| Files it can read | SSH keys, cloud credentials, kubeconfig, git/GitHub tokens, registry tokens, GPG keys, browser profiles, shell history, project `.env`, directories outside the project |
| Files it can change | home directory, shell startup files, `~/.ssh`, the project's parent, system directories |
| Secrets within reach | secret-looking environment variables, SSH agent socket, environment of other processes |
| Network | outbound access to an arbitrary host (direct or through a proxy), DNS and UDP egress, cloud metadata service, local database ports, host services through the container gateway |
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

## What the score means, and what it does not

Starts at 100. Each exposure subtracts: critical 25, high 10, medium 4, low 1.
Any critical exposure caps the grade at D.

- **It measures reach, not wall strength.** A container and a virtual machine can score the same,
  yet a VM survives a kernel exploit that a container does not.
- **A good score is not proof of safety.** The tool only finds the channels it knows about.
  Three probes were added during the study after a sandbox wrongly scored 100.
- **Inside a container, only host files count.** Since 0.3.0 the tool reads the mount table to tell
  the container's own disposable files from directories mounted in from the host, and reports the
  former as not applicable. This is a heuristic. "Running as root" counts as medium and
  "system directories writable" as low there. The study above was run with 0.2.0, which flagged
  some container-internal paths, so its Docker scores are slightly too low.

## Contributing

Each probe is a few lines in `leashcheck.py`. If you know a way out of a sandbox that the tool
misses, open an issue or a pull request.

```sh
python3 -m unittest
```

MIT licence.
