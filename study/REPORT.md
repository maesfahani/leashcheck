# Which isolation is safest for an AI coding agent?

Study run on 2026-11-12 with leashcheck 0.1.0 on one Ubuntu machine (kernel 7.0, x86-64).
Eight configurations were measured.

## Verdict

**A hardened Docker container was the safest configuration measured: 96/100, grade A, with no real
exposure.** Its one flagged item is a false positive (see finding 7).

The container itself is not what makes it safe. The same Docker, started carelessly, scored 0 and was
worse than using no sandbox at all. What matters is what you mount and which flags you pass.

| Rank | Configuration | Score | Real exposures left |
|---|---|---|---|
| 1 | Docker, hardened | 96 / A | None found |
| 2 | Docker, hardened, with network | 82 / B | Open outbound network and DNS |
| 3 | Landlock, files + TCP blocked + clean environment | 76 / B | SSH agent, user session bus, UDP |
| 4 | Docker, default flags | 53 / D | Open network, DNS, root inside the container (score understated, see finding 7) |
| 5 | Landlock, files only | 52 / D | The three above plus open network, local databases, environment variables |
| 6 | Bare | 0 / F | 15 exposures, 2 critical |
| 6 | Bare, clean environment | 0 / F | 14 exposures, 2 critical |
| 8 | Docker, careless | 0 / F | 14 exposures, 3 critical, including root on the host |

The hardened container was started like this:

```sh
docker run --rm -v "$PROJECT":/w -w /w \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  --network none --read-only --tmpfs /tmp IMAGE COMMAND
```

One caveat on practicality: `--network none` also cuts off the model API and package registries.
Configuration 8 shows the cost of simply turning the network back on: every file, socket and
privilege protection held, but outbound access to any host returned, so anything the agent can read
in the project can be sent out. The middle ground, an allowlist proxy, was not measured.

## Measured results

Cells show status only. Raw results contain local paths and are not published.

| Probe | 1-bare | 2-bare-clean-env | 3-landlock-files | 4-landlock-full | 5-docker-default | 6-docker-hardened | 7-docker-careless | 8-docker-hardened-net |
|---|---|---|---|---|---|---|---|---|
| **Score / grade** | **0 / F** | **0 / F** | **52 / D** | **76 / B** | **53 / D** | **96 / A** | **0 / F** | **82 / B** |
| exposed, critical | 2 | 2 | 0 | 0 | 0 | 0 | 3 | 0 |
| exposed, high | 9 | 8 | 4 | 2 | 3 | 0 | 5 | 1 |
| exposed, medium | 4 | 4 | 2 | 1 | 4 | 1 | 5 | 2 |
| exposed, low | 0 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |
| **Files it can read** | | | | | | | | |
| SSH private keys | EXPOSED (critical) | EXPOSED (critical) | - | - | - | - | EXPOSED (critical) | - |
| Cloud provider credentials | - | - | - | - | - | - | - | - |
| Kubernetes config | - | - | - | - | - | - | - | - |
| Git / GitHub credentials | EXPOSED (critical) | EXPOSED (critical) | ok | ok | - | - | EXPOSED (critical) | - |
| Package registry and Docker tokens | - | - | - | - | - | - | - | - |
| GPG private keys / password store | - | - | ok | ok | - | - | - | - |
| Browser profiles (cookies, sessions) | EXPOSED (high) | EXPOSED (high) | ok | ok | - | - | EXPOSED (high) | - |
| Shell history | EXPOSED (medium) | EXPOSED (medium) | ok | ok | - | - | EXPOSED (medium) | - |
| Project .env files | - | - | - | - | - | - | - | - |
| Directories outside the project | ok | ok | ok | ok | EXPOSED (medium) | EXPOSED (medium) | ok | EXPOSED (medium) |
| **Files it can change or delete** | | | | | | | | |
| Home directory | EXPOSED (high) | EXPOSED (high) | ok | ok | EXPOSED (high) | ok | EXPOSED (high) | ok |
| Shell startup files and git config | EXPOSED (high) | EXPOSED (high) | ok | ok | EXPOSED (high) | - | EXPOSED (high) | - |
| ~/.ssh (authorized_keys, config) | EXPOSED (high) | EXPOSED (high) | ok | ok | - | - | EXPOSED (high) | - |
| Parent of the project directory | EXPOSED (medium) | EXPOSED (medium) | ok | ok | EXPOSED (medium) | ok | EXPOSED (medium) | ok |
| System directories | ok | ok | ok | ok | EXPOSED (low) | ok | EXPOSED (low) | ok |
| **Secrets within reach** | | | | | | | | |
| Secret-looking environment variables | EXPOSED (high) | ok | EXPOSED (high) | ok | ok | ok | ok | ok |
| SSH agent | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | - | - | - | - |
| Environment of other processes | EXPOSED (high) | EXPOSED (high) | ok | ok | ok | ok | ok | ok |
| **Network** | | | | | | | | |
| Outbound access to an arbitrary host | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | ok | EXPOSED (high) | ok | EXPOSED (high) | EXPOSED (high) |
| DNS / UDP egress | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | ok | EXPOSED (medium) | EXPOSED (medium) |
| Cloud metadata service | ok | ok | ok | ok | ok | ok | ok | ok |
| Local services on this machine | EXPOSED (medium) | EXPOSED (medium) | EXPOSED (medium) | ok | ok | ok | EXPOSED (medium) | ok |
| **Privilege** | | | | | | | | |
| Running as root | ok | ok | ok | ok | EXPOSED (medium) | ok | EXPOSED (medium) | ok |
| Passwordless sudo | ok | ok | ok | ok | - | - | - | - |
| Container runtime socket | ok | ok | ok | ok | ok | ok | EXPOSED (critical) | ok |
| User session bus (systemd --user, D-Bus) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | EXPOSED (high) | ok | ok | ok | ok |
| CAP_SYS_ADMIN capability | ok | ok | ok | ok | ok | ok | ok | ok |

`-` means the thing probed for does not exist or is invisible in that environment; `ok` means it exists and is blocked.

The eight configurations:

| Name | What it is |
|---|---|
| 1-bare | The agent runs as the normal user, as most people run it today |
| 2-bare-clean-env | Same, started with `env -i` so no environment variables are inherited |
| 3-landlock-files | Landlock sandbox: project read-write, `/usr` and `/etc` read-only, everything else invisible; network and environment untouched |
| 4-landlock-full | Configuration 3 plus all TCP denied and a clean environment |
| 5-docker-default | `docker run -v project:/w`, nothing else: root user, default capabilities, default network |
| 6-docker-hardened | Project mount only, non-root user, all capabilities dropped, no network, read-only root filesystem |
| 7-docker-careless | Home directory and Docker socket mounted, host network |
| 8-docker-hardened-net | Configuration 6 with Docker's default bridge network, and a separate project directory mounted read-write |

## Findings

1. **Restricting the filesystem is the largest single step.** Under Landlock it closed all eight file
   exposures (four read, four write), including both critical ones, and stopped the agent reading
   other processes' environments. Score went from 0 to 52.

2. **Cleaning the environment alone achieves almost nothing.** It hid one environment variable.
   The SSH agent stayed usable, because its socket sits at a well-known path that needs no variable to find.

3. **A path-based sandbox does not block Unix sockets; a container does.** Under Landlock, with `/run`
   not allowed, the probe still connected to the SSH agent (three keys usable) and to the user session
   bus. Through the session bus a process can ask `systemd --user` to start a command outside the
   sandbox, which defeats the sandbox. All three Docker configurations blocked both, including the
   careless one, because a container has its own `/run`.

4. **Blocking TCP leaves UDP open; removing the network closes it.** With Landlock denying all TCP,
   a DNS query sent directly to a public resolver was still answered. With `--network none` it was not.

5. **A careless container is worse than no container.** Mounting the home directory brought back
   every file exposure of the bare machine. Mounting the Docker socket added a third critical one:
   the socket gives root on the host, which the bare user account did not have.

6. **With the network on, a hardened container leaks only through the network.** Configuration 8
   differs from 6 in two exposures: outbound access to an arbitrary host, and DNS. Local databases
   on the host showed as unreachable, but the probe tests `127.0.0.1`, which inside a container is
   the container's own loopback. Host services listening on all interfaces may still be reachable
   through the bridge gateway; the tool does not test that yet.

7. **The tool under-scores containers.** Inside a container it cannot yet tell the container's own
   disposable files from host files. Four of the Docker-default exposures (home directory, startup
   files, parent directory, directories outside the project) and the one flagged in each hardened run concern
   only the container's own filesystem. Read correctly, Docker default protects all host files and
   its real weaknesses are open network, DNS and running as root.

8. **Unprivileged sandboxes do not work out of the box on this Ubuntu.** bubblewrap failed with
   "setting up uid map: Permission denied" because AppArmor restricts unprivileged user namespaces.
   Tools built on bubblewrap, including Claude Code's sandbox mode, could not be measured here.

## Not measured

| Configuration | Why |
|---|---|
| bubblewrap / Claude Code sandbox mode | Blocked by the AppArmor restriction above |
| Container with an allowlist proxy | Not set up; this is the realistic way to run an agent inside a container |
| Virtual machine, remote machine | Not run |

## Limits of this study

- **Reach, not wall strength.** leashcheck measures what the agent can touch from inside. It cannot
  measure how hard the boundary is to break. A container and a VM can score the same here, yet a VM
  survives a kernel exploit that a container does not. On that axis a disposable VM or remote machine
  is stronger than any configuration above, by reasoning and not by this data.
- **One machine, one run.** No cloud credentials or Kubernetes config exist here, so those probes say nothing.
- **The tool changed during the study.** The first run gave configuration 4 a score of 100.
  That was wrong: the tool did not yet test agent sockets at well-known paths, the session bus,
  or UDP. Those probes were added and configurations 1 to 4 rerun. Other untested channels probably remain.
- **One probe was uninformative.** "Directories outside the project" shows `ok` even when bare,
  because the project's parent directory happens to contain nothing else.
- **Scores are a rough guide.** The weights (25/10/4/1) are a judgment call, not derived from incident data.

## Reproduce

```sh
study/run_local.sh          # configurations 1-4, no root
sudo study/run_docker.sh    # configurations 5-8 (8 needs ~/proj or PROJ=...)
python3 study/report.py     # redacted matrix
```
