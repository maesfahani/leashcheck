#!/usr/bin/env bash
# Docker configurations. Needs access to the Docker daemon, so usually:
#     sudo study/run_docker.sh
# The "careless" run mounts your home directory and the Docker socket into a
# container on purpose, to show what that costs. leashcheck only probes; it
# changes nothing.
#
# Usage: run_docker.sh [all|5|6|7|8]     (default: all)
#        PROJ=/path/to/project run_docker.sh 8     (default project: ~/proj)
set -u
ONLY=${1:-all}
want() { [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }
cd "$(dirname "$0")/.."
P=$PWD
R=$P/study/results
mkdir -p "$R"
IMG=python:3.12-slim

REAL_USER=${SUDO_USER:-$(id -un)}
REAL_UID=$(id -u "$REAL_USER")
REAL_GID=$(id -g "$REAL_USER")
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

docker info >/dev/null 2>&1 || { echo "cannot reach the Docker daemon; run with sudo" >&2; exit 1; }
docker pull -q "$IMG" >/dev/null

RUN=(docker run --rm -e PYTHONDONTWRITEBYTECODE=1)
CHECK=(python leashcheck.py --json --timeout 2)

want 5 && {
echo "5 docker, default"
"${RUN[@]}" -v "$P":/w -w /w "$IMG" "${CHECK[@]}" > "$R/5-docker-default.json"
}

want 6 && {
echo "6 docker, hardened"
"${RUN[@]}" -v "$P":/w -w /w --user "$REAL_UID:$REAL_GID" --cap-drop ALL \
    --security-opt no-new-privileges --network none --read-only --tmpfs /tmp \
    "$IMG" "${CHECK[@]}" > "$R/6-docker-hardened.json"
}

want 7 && {
echo "7 docker, careless (home + docker socket mounted, host network)"
"${RUN[@]}" -v "$REAL_HOME":"$REAL_HOME" -e HOME="$REAL_HOME" -w "$P" \
    -v /var/run/docker.sock:/var/run/docker.sock --network host \
    "$IMG" "${CHECK[@]}" > "$R/7-docker-careless.json"
}

# Hardened like 6, but with Docker's default bridge network, and a separate
# project directory mounted read-write. leashcheck itself is mounted read-only.
want 8 && {
PROJ=${PROJ:-$REAL_HOME/proj}
if [ -d "$PROJ" ]; then
echo "8 docker, hardened + network, project $PROJ"
"${RUN[@]}" -v "$PROJ":/proj -w /proj -v "$P/leashcheck.py":/opt/leashcheck.py:ro \
    --user "$REAL_UID:$REAL_GID" --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp \
    "$IMG" python /opt/leashcheck.py --json --timeout 2 > "$R/8-docker-hardened-net.json"
else
echo "8 skipped: project directory $PROJ does not exist" >&2
fi
}

chown "$REAL_UID:$REAL_GID" "$R"/*.json
ls -l "$R"
