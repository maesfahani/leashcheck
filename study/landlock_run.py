#!/usr/bin/env python3
"""Run a command inside a Landlock sandbox. Linux only, no root needed.

    landlock_run.py --ro /usr --ro /etc --rw ./project [--no-tcp] -- cmd args...

Everything not listed with --ro (read + execute) or --rw (full access) becomes
inaccessible to the command and its children. --no-tcp also denies all TCP
connect and bind (kernel Landlock ABI 4+).

This is a minimal launcher for the leashcheck study, representing the
"OS-level sandbox" class of isolation. It is not a hardened product.
"""
import argparse
import ctypes
import os
import sys

SYS_CREATE_RULESET, SYS_ADD_RULE, SYS_RESTRICT_SELF = 444, 445, 446
RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

EXECUTE, WRITE_FILE, READ_FILE, READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
REFER, TRUNCATE, IOCTL_DEV = 1 << 13, 1 << 14, 1 << 15
FS_ABI1 = (1 << 13) - 1  # bits 0..12
FILE_RIGHTS = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
NET_BIND_TCP, NET_CONNECT_TCP = 1 << 0, 1 << 1
SCOPE_ABSTRACT_UNIX, SCOPE_SIGNAL = 1 << 0, 1 << 1


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


def check(ret, what):
    if ret < 0:
        err = ctypes.get_errno()
        sys.exit("landlock_run: %s failed: %s" % (what, os.strerror(err)))
    return ret


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ro", action="append", default=[], metavar="PATH")
    ap.add_argument("--rw", action="append", default=[], metavar="PATH")
    ap.add_argument("--no-tcp", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not cmd:
        ap.error("no command given")

    abi = check(libc.syscall(SYS_CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(1)), "ABI query")
    fs_all = FS_ABI1 | (REFER if abi >= 2 else 0) | (TRUNCATE if abi >= 3 else 0) | (IOCTL_DEV if abi >= 5 else 0)
    attr = RulesetAttr(handled_access_fs=fs_all)
    size = 8
    if abi >= 4:
        size = 16
        if args.no_tcp:
            attr.handled_access_net = NET_BIND_TCP | NET_CONNECT_TCP  # no port rules added: all denied
    elif args.no_tcp:
        sys.exit("landlock_run: --no-tcp needs Landlock ABI 4+, kernel has %d" % abi)
    if abi >= 6:
        size = 24
        attr.scoped = SCOPE_ABSTRACT_UNIX | SCOPE_SIGNAL
    ruleset = check(libc.syscall(SYS_CREATE_RULESET, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0)),
                    "create_ruleset")

    ro = (EXECUTE | READ_FILE | READ_DIR) & fs_all
    for paths, access in ((args.ro, ro), (args.rw, fs_all)):
        for path in paths:
            if not os.path.exists(path):
                continue
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            allowed = access if os.path.isdir(path) else access & FILE_RIGHTS
            rule = PathBeneathAttr(allowed_access=allowed, parent_fd=fd)
            check(libc.syscall(SYS_ADD_RULE, ctypes.c_int(ruleset), ctypes.c_int(RULE_PATH_BENEATH),
                               ctypes.byref(rule), ctypes.c_uint32(0)), "add_rule %s" % path)
            os.close(fd)

    check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "no_new_privs")
    check(libc.syscall(SYS_RESTRICT_SELF, ctypes.c_int(ruleset), ctypes.c_uint32(0)), "restrict_self")
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
