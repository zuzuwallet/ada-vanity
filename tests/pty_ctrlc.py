#!/usr/bin/env python3

# Copyright (c) 2026 ZuZu Wallet
# https://ZuZuWallet.com
# Support@ZuZuWallet.com
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Ctrl-C on a PTY: echo returns, and no mnemonic or unsaved address is printed."""

import fcntl
import os
import pty
import select
import subprocess
import sys
import termios
import time


def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def run_case(args, before_password, label, forbid, prompt=b"Passphrase:"):
    binary = os.environ["ADA_VANITY_BIN"]
    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        [binary, *args],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=preexec,
        close_fds=True,
    )
    buf = b""

    def read_until(token, timeout):
        nonlocal buf
        deadline = time.time() + timeout
        while time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as err:
                    fail(f"{label}: read failed: {err}")
                if not chunk:
                    return False
                buf += chunk
                if token in buf:
                    return True
            if proc.poll() is not None:
                return token in buf
        return False

    try:
        if before_password is not None:
            before_password(master, read_until)
        if not read_until(prompt, 90):
            fail(f"{label}: prompt did not appear")
        time.sleep(0.05)
        echo_during = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
        if echo_during:
            fail(f"{label}: echo was still on during the passphrase prompt")
        os.write(master, b"\x03")
        rc = proc.wait(timeout=20)
        deadline = time.time() + 1
        while time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if not ready:
                break
            chunk = os.read(master, 4096)
            if not chunk:
                break
            buf += chunk
        echo_after = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
        text = buf.decode(errors="replace")
        if not echo_after:
            fail(f"{label}: echo was off after Ctrl-C\n{text}")
        if rc == 0 or "search cancelled" not in text:
            fail(f"{label}: expected a cancelled exit, rc={rc}\n{text}")
        for token in forbid:
            if token in text:
                fail(f"{label}: output contained {token!r}\n{text}")
        return text
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


def type_export(master, read_until):
    if not read_until(b"Type EXPORT to continue:", 20):
        fail("export: EXPORT confirmation did not appear")
    os.write(master, b"EXPORT\n")


def run_occupied_output(wallet):
    """A file created at the passphrase prompt must not be treated as this wallet."""
    binary = os.environ["ADA_VANITY_BIN"]
    master, slave = pty.openpty()
    err_read, err_write = os.pipe()

    def preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        [binary, "generate", "addr1qy", "--threads", "1", "--output", wallet],
        stdin=slave,
        stdout=slave,
        stderr=err_write,
        preexec_fn=preexec,
        close_fds=True,
    )
    os.close(err_write)
    stdout = b""
    stderr = b""

    open_fds = [master, err_read]

    def pump(timeout):
        nonlocal stdout, stderr
        deadline = time.time() + timeout
        while time.time() < deadline and open_fds:
            ready, _, _ = select.select(open_fds, [], [], 0.2)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            for fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as err:
                    fail(f"occupied: read failed: {err}")
                if not chunk:
                    open_fds.remove(fd)
                    continue
                if fd == master:
                    stdout += chunk
                else:
                    stderr += chunk

    try:
        deadline = time.time() + 90
        while b"Passphrase:" not in stdout and time.time() < deadline:
            pump(0.2)
        if b"Passphrase:" not in stdout:
            fail(
                "occupied: passphrase prompt did not appear\n"
                f"stdout:\n{stdout.decode(errors='replace')}\n"
                f"stderr:\n{stderr.decode(errors='replace')}"
            )
        time.sleep(0.05)
        marker = b"not-the-vanity-wallet\n"
        with open(wallet, "wb") as handle:
            handle.write(marker)
        passphrase = b"correct horse battery\n"
        os.write(master, passphrase)
        confirm_deadline = time.time() + 15
        while b"Confirm passphrase:" not in stdout and time.time() < confirm_deadline:
            pump(0.2)
        if b"Confirm passphrase:" not in stdout:
            fail(
                "occupied: confirmation prompt did not appear\n"
                f"stdout:\n{stdout.decode(errors='replace')}"
            )
        time.sleep(0.05)
        os.write(master, passphrase)
        wait_deadline = time.time() + 20
        while proc.poll() is None and time.time() < wait_deadline:
            pump(0.2)
        if proc.poll() is None:
            proc.kill()
            fail("occupied: generate did not exit")
        pump(0.5)
        rc = proc.wait(timeout=5)
        out_text = stdout.decode(errors="replace")
        err_text = stderr.decode(errors="replace")
        if rc == 0:
            fail(f"occupied: generate succeeded\nstdout:\n{out_text}\nstderr:\n{err_text}")
        if "FOUND" in out_text or "Address:" in out_text or "Mnemonic:" in out_text:
            fail(f"occupied: address was printed\nstdout:\n{out_text}")
        if "output file already exists" not in err_text:
            fail(f"occupied: missing OutputExists error\nstderr:\n{err_text}")
        if "Wallet was not saved successfully." not in err_text:
            fail(f"occupied: missing save failure\nstderr:\n{err_text}")
        with open(wallet, "rb") as handle:
            got = handle.read()
        if got != marker:
            fail(f"occupied: planted file changed: {got!r}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)
        os.close(err_read)


def run_recover_ok():
    """A 24-word phrase is not echoed, and the public address is rebuilt."""
    binary = os.environ["ADA_VANITY_BIN"]
    mnemonic = os.environ["ADA_RECOVER_MNEMONIC"]
    expected = os.environ["ADA_RECOVER_ADDRESS"]
    master, slave = pty.openpty()

    def preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        [binary, "recover", "--network", "mainnet", "--account", "0", "--index", "20"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=preexec,
        close_fds=True,
    )
    buf = b""

    def read_for(seconds):
        nonlocal buf
        deadline = time.time() + seconds
        while time.time() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as err:
                    fail(f"recover: read failed: {err}")
                if not chunk:
                    return
                buf += chunk
            elif proc.poll() is not None:
                return

    try:
        deadline = time.time() + 20
        while b"Mnemonic:" not in buf and time.time() < deadline:
            read_for(0.2)
        if b"Mnemonic:" not in buf:
            fail("recover: mnemonic prompt did not appear")
        time.sleep(0.05)
        if termios.tcgetattr(slave)[3] & termios.ECHO:
            fail("recover: echo was still on during the mnemonic prompt")
        payload = mnemonic.encode() + b"\n"
        while payload:
            written = os.write(master, payload)
            payload = payload[written:]
        wait_deadline = time.time() + 30
        while proc.poll() is None and time.time() < wait_deadline:
            read_for(0.2)
        if proc.poll() is None:
            proc.kill()
            fail("recover: did not exit")
        read_for(0.5)
        rc = proc.wait(timeout=5)
        if (termios.tcgetattr(slave)[3] & termios.ECHO) == 0:
            fail("recover: echo was off after the command")
        text = buf.decode(errors="replace")
        if mnemonic in text:
            fail("recover: mnemonic was echoed")
        if rc != 0:
            fail(f"recover: exit {rc}")
        required = (
            "HD derivation: PASS",
            "Payment credential: PASS",
            "Stake credential: PASS",
            "Address construction: PASS",
            expected,
            "m/1852'/1815'/0'/0/20",
            "m/1852'/1815'/0'/2/0",
            "Cardano Icarus / CIP-3",
            "NOT guaranteed",
            "not sufficient for practical recovery",
            "Back up the exact payment derivation index/path.",
            "will not discover payment index 20",
            "Recovery test:",
            "PENDING",
        )
        missing = [token for token in required if token not in text]
        if missing:
            fail("recover: missing " + ", ".join(missing))
        if "advanced setting" in text:
            fail("recover: account 0 was labeled advanced")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


def main():
    missing = f"/tmp/ada-vanity-pty-missing-{os.getpid()}.json"
    wallet = f"/tmp/ada-vanity-pty-generate-{os.getpid()}.json"
    for path in (missing, wallet):
        if os.path.exists(path):
            os.remove(path)
    try:
        run_case(["verify", missing], None, "verify", ("Mnemonic:", "Address:", "FOUND"))
        run_case(["export", missing], type_export, "export", ("Mnemonic:",))
        run_case(
            ["generate", "addr1qy", "--threads", "1", "--output", wallet],
            None,
            "generate",
            ("Address:", "Mnemonic:", "FOUND"),
        )
        run_case(
            ["recover", "--index", "20"],
            None,
            "recover-cancel",
            ("Address:", "FOUND", "abandon", "HD derivation"),
            b"Mnemonic:",
        )
        run_recover_ok()
        if os.path.exists(wallet):
            fail(f"generate: wallet was created at {wallet}")
        run_occupied_output(wallet)
    finally:
        for path in (missing, wallet):
            if os.path.exists(path):
                os.remove(path)
    print("PTY_OK")


if __name__ == "__main__":
    main()
