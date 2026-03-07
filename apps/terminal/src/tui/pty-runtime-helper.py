#!/usr/bin/env python3

import argparse
import base64
import json
import os
import pty
import queue
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
from typing import Any


def emit(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def set_winsize(fd: int, cols: int, rows: int) -> None:
    winsize = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl = __import__("fcntl")
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except Exception:
        return


def stdin_reader(command_queue: "queue.Queue[dict[str, Any]]") -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            command_queue.put(json.loads(raw))
        except Exception as exc:
            emit({"type": "error", "error": f"invalid helper command: {exc}"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--cols", type=int, default=120)
    parser.add_argument("--rows", type=int, default=40)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        emit({"type": "error", "error": "no PTY command provided"})
        return 1

    master_fd, slave_fd = pty.openpty()
    set_winsize(slave_fd, max(args.cols, 20), max(args.rows, 10))

    proc = subprocess.Popen(
        command,
        cwd=args.cwd,
        env=os.environ.copy(),
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave_fd)

    command_queue: "queue.Queue[dict[str, Any]]" = queue.Queue()
    threading.Thread(target=stdin_reader, args=(command_queue,), daemon=True).start()
    emit({"type": "ready"})

    try:
        while True:
            while True:
                try:
                    message = command_queue.get_nowait()
                except queue.Empty:
                    break

                msg_type = message.get("type")
                if msg_type == "input":
                    try:
                        data = base64.b64decode(message.get("data", ""))
                        os.write(master_fd, data)
                    except Exception as exc:
                        emit({"type": "error", "error": f"input write failed: {exc}"})
                elif msg_type == "resize":
                    cols = int(message.get("cols", args.cols))
                    rows = int(message.get("rows", args.rows))
                    set_winsize(master_fd, max(cols, 20), max(rows, 10))
                elif msg_type == "kill":
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except Exception:
                        proc.terminate()

            readable, _, _ = select.select([master_fd], [], [], 0.05)
            if readable:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    data = b""
                if data:
                    emit({"type": "output", "data": base64.b64encode(data).decode("ascii")})

            exit_code = proc.poll()
            if exit_code is not None:
                while True:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        data = b""
                    if not data:
                        break
                    emit({"type": "output", "data": base64.b64encode(data).decode("ascii")})
                emit({"type": "exit", "code": exit_code, "signal": None})
                return 0
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
