# Which isolation is safest for an AI coding agent?

Study run on 2026-11-12 with leashcheck 0.1.0 on one Ubuntu machine (kernel 7.0, x86-64).

## Verdict so far

Only four of the planned seven configurations are measured. The three Docker ones need root on this
machine and have not been run yet, so the overall "safest option" is not settled by data.

Of what was measured, **Landlock with files and TCP restricted plus a clean environment is the safest
(76/100, grade B)**, against 0/100 for running the agent bare. It still leaves three holes open:
the SSH agent, the user session bus, and UDP.

## Measured results

Cells show status only. Raw results contain local paths and are not published.

| Probe | 1-bare | 2-bare-clean-env | 3-landlock-files | 4-landlock-full |
|---|---|---|---|---|
| **Score / grade** | **0 / F** | **0 / F** | **52 / D** | **76 / B** |
| exposed, critical | 2 | 2 | 0 | 0 |
| exposed, high | 9 | 8 | 4 | 2 |
| exposed, medium | 4 | 4 | 2 | 1 |
| exposed, low | 0 | 0 | 0 | 0 |
| **Files it can read** | | | | |
| SSH private keys | EXPOSED (critical) | EXPOSED (critical) | - | - |
| Cloud provider credentials | - | - | - | - |
| Kubernetes config | - | - | - | - |
| Git / GitHub credentials | EXPOSED (critical) | EXPOSED (critical) | ok | ok |
| Package registry and Docker tokens | - | - | - | - |
| GPG private keys / password store | - | - | ok | ok |
| Browser profiles (cookies, sessions) | EXPOSED (high) | EXPOSED (high) | ok | ok |
| Shell history | EXPOSED (medium) | EXPOSED (medium) | ok | ok |
| Project .env files | - | - | - | - |
| Directories outside the project | ok | ok | ok | ok |
| **Files it can change or delete** | | | | |
| Home directory | EXPOSED (high) | EXPOSED (high) | ok | ok |
| Shell startup files and git config | EXPOSED (high) | EXPOSED (high) | ok | ok |
| ~/.ssh (authorized_keys, config) | EXPOSED (high) | EXPOSED (high) | ok | ok |
| Parent of the project directory | EXPOSED (medium) | EXPOSED (medium) | ok | ok |
| System directories | ok | ok | ok | ok |
| **Secrets within reach** | | | | |
| Secret-looking environment variables | EXPOSED (high) | ok | EXPOSED (high) | ok |
| SSH agent | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) |
| Environment of other processes | EXPOSED (high) | EXPOSED (high) | ok | ok |
| **Network** | | | | |
| Outbound access to an arbitrary host | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | ok |
| DNS / UDP egress | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) |
| Cloud metadata service | ok | ok | ok | ok |
| Local services on this machine | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | ok |
| **Privilege** | | | | |
| Running as root | ok | ok | ok | ok |
| Passwordless sudo | ok | ok | ok | ok |
| Container runtime socket | ok | ok | ok | ok |
| User session bus (systemd --user, D-Bus) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) |
| CAP_SYS_ADMIN capability | ok | ok | ok | ok |

`-` means the thing probed for does not exist on this machine or is invisible; `ok` means it exists and is blocked.

The four configurations:

| Name | What it is |
|---|---|
| 1-bare | The agent runs as the normal user, as most people run it today |
| 2-bare-clean-env | Same, started with `env -i` so no environment variables are inherited |
| 3-landlock-files | Landlock sandbox: project read-write, `/usr` and `/etc` read-only, everything else invisible; network and environment untouched |
| 4-landlock-full | Configuration 3 plus all TCP denied and a clean environment |

## Findings

1. **Restricting the filesystem is the largest single step.** It closed all eight file exposures
   (four read, four write), including both critical ones, and stopped the agent reading other
   processes' environments. Score went from 0 to 52.

2. **Cleaning the environment alone achieves almost nothing.** It hid one environment variable.
   The SSH agent stayed usable, because its socket sits at a well-known path that needs no variable to find.

3. **A path-based sandbox does not block Unix sockets.** Under Landlock, with `/run` not allowed,
   the probe still connected to the SSH agent (three keys usable) and to the user session bus.
   The session bus matters most: through it a process can ask `systemd --user` to start a command
   outside the sandbox, which defeats the sandbox. Closing this needs a private `/run` and `/tmp`,
   which means a mount namespace: a container, or bubblewrap.

4. **Blocking TCP leaves UDP open.** With all TCP denied, a DNS query sent directly to a public
   resolver was still answered. Data can leave that way. Closing it needs a network namespace
   or a firewall rule, not Landlock.

5. **Unprivileged sandboxes do not work out of the box on this Ubuntu.** bubblewrap failed with
   "setting up uid map: Permission denied" because AppArmor restricts unprivileged user namespaces.
   Tools built on bubblewrap, including Claude Code's sandbox mode, could not be measured here for that reason.

## Not measured

| Configuration | Status |
|---|---|
| Docker, default flags | Script ready (`study/run_docker.sh`), needs root |
| Docker, hardened (non-root, no capabilities, no network, read-only) | Same |
| Docker, careless (home and Docker socket mounted) | Same |
| bubblewrap / Claude Code sandbox mode | Blocked by the AppArmor restriction above |
| Virtual machine | Not run |

A container has its own mount, PID and network namespaces, so by design it should close the three
holes Landlock left. That is an expectation until the Docker runs confirm it.

## Limits of this study

- **Reach, not wall strength.** leashcheck measures what the agent can touch from inside. It cannot
  measure how hard the boundary is to break. A container and a VM can score the same here, yet a VM
  survives a kernel exploit that a container does not. On that axis a disposable VM or remote machine
  is the strongest option, by reasoning and not by this data.
- **One machine, one run.** Results depend on what this machine has: no cloud credentials or
  Kubernetes config exist here, so those probes say nothing.
- **The tool changed during the study.** The first run gave configuration 4 a score of 100.
  That was wrong: the tool did not yet test agent sockets at well-known paths, the session bus,
  or UDP. Those three probes were added and all four configurations were rerun. Other untested
  channels probably remain.
- **One probe was uninformative.** "Directories outside the project" shows `ok` even when bare,
  because the project's parent directory happens to contain nothing else.
- **Scores are a rough guide.** The weights (25/10/4/1) are a judgment call, not derived from incident data.

## Reproduce

```sh
study/run_local.sh          # configurations 1-4, no root
sudo study/run_docker.sh    # configurations 5-7
python3 study/report.py     # redacted matrix
```
