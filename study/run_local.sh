#!/usr/bin/env bash
# Configurations that need no root. Results (which contain local paths and
# variable names) go to study/results/, which is git-ignored.
set -u
cd "$(dirname "$0")/.."
P=$PWD
R=$P/study/results
mkdir -p "$R"
export PYTHONDONTWRITEBYTECODE=1

CHECK=(python3 "$P/leashcheck.py" --json --timeout 2 --project "$P")
LANDLOCK=(python3 "$P/study/landlock_run.py" --ro /usr --ro /bin --ro /lib --ro /lib64 --ro /etc
          --ro /proc/self --rw /dev/null --rw "$P")
CLEAN=(env -i HOME="$HOME" PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1)

echo "1 bare";                 "${CHECK[@]}"                                     > "$R/1-bare.json"
echo "2 bare, clean env";      "${CLEAN[@]}" "${CHECK[@]}"                       > "$R/2-bare-clean-env.json"
echo "3 landlock, files only"; "${LANDLOCK[@]}" -- "${CHECK[@]}"                 > "$R/3-landlock-files.json"
echo "4 landlock, full";       "${CLEAN[@]}" "${LANDLOCK[@]}" --no-tcp -- "${CHECK[@]}" > "$R/4-landlock-full.json"
ls -l "$R"
