# leash

**Run Claude Code with full internet access and your project, and nothing else from your machine.**

```sh
cd ~/my-project
leash
```

Status: experimental. Linux with Docker only.

## Install

```sh
git clone https://github.com/maesfahani/leashcheck
ln -s "$PWD/leashcheck/leash/leash" ~/.local/bin/leash
```

The first run builds the image (a few minutes). The first start asks you to log in to Claude;
the login is stored in a Docker volume that only the sandbox sees.

| Command | What it does |
|---|---|
| `leash` | Start Claude Code in the current directory. Extra arguments go to `claude`. |
| `leash audit` | Run leashcheck inside the same sandbox, to see what the agent can reach |
| `leash shell` | Open a shell inside the same sandbox |
| `leash build` | Rebuild the image, which also updates Claude Code |
| `leash reset` | Delete the sandbox home: Claude login, settings, history |

## What the agent gets

- The current directory, read-write, at the same path.
- The internet.
- Its own private home directory, kept between runs.
- Your git name and email for commits. `ANTHROPIC_API_KEY`, if it is set.

## What it does not get

- Your home directory: no SSH keys, git credentials, cloud credentials, browser profiles, shell history.
- Your SSH agent, the Docker socket, the user session bus.
- Root, or any Linux capability. It runs as your user id with `no-new-privileges`.
- The host and the local network. A firewall inside the container rejects private address
  ranges and the cloud metadata address, so local databases and other machines on your LAN are out of reach.
- Other processes on the machine.
- Write access to `.git/hooks` and `.git/config`, so it cannot plant a hook that runs later on the host.
  Consequence: `git config`, `git remote add` and `git push -u` fail inside. `LEASH_GIT_RW=1` turns this off.

## What risk remains

There is no such thing as zero risk. These are left, by design or by nature:

- **The project itself.** The agent can change or delete anything in the mounted directory. Commit first.
- **Code that you run later.** A changed `Makefile`, `package.json` script or test runs with your
  full rights when you execute it outside the sandbox. Review the diff first.
- **Exfiltration.** The internet is open, so whatever the agent can read (the project, including
  any `.env` in it, and its own Claude login) could be sent anywhere. A prompt injection in a web
  page or dependency could cause that.
- **The container boundary.** A container shares the host kernel. A kernel exploit could escape it;
  a virtual machine would not have that weakness.
- **`sudo docker`.** If your user cannot reach Docker directly, leash calls it through sudo.
  The launcher is short; read it before trusting it with that.

## Check it yourself

```sh
cd ~/my-project && leash audit
```

Expected: outbound network and DNS show as exposed, because internet access is the point.
Everything else should be protected or absent. If not, please open an issue.

On the machine where leash was developed, which scores 0/100 without a sandbox:

```text
NETWORK
  ✗ HIGH      Outbound access to an arbitrary host          direct connection to example.com:443
  ✗ MEDIUM    DNS / UDP egress                              example.com resolves
  ✓ ok        Cloud metadata service                        not reachable
  ✓ ok        Local services on this machine                no common database ports open on 127.0.0.1
  ✓ ok        Host services through the container gateway   no common service ports reachable on the gateway
PRIVILEGE
  ✓ ok        Running as root                               uid 1000
  ✓ ok        Container runtime socket                      no Docker, Podman or LXD socket reachable
  ✓ ok        User session bus (systemd --user, D-Bus)      session bus not reachable
  ✓ ok        CAP_SYS_ADMIN capability                      not held

Score 86/100, grade B   2 exposed (1 high, 1 medium), 10 protected, 16 n/a
```

Every file probe reported "not present or not visible".
