from __future__ import annotations

import argparse
import asyncio
import socket
import time
from http.client import HTTPConnection


def run_http(host: str, port: int) -> None:
    connection = HTTPConnection(host, port, timeout=5)
    connection.request("GET", "/", headers={"User-Agent": "SentinelMeshDemo/1.0"})
    response = connection.getresponse()
    print(f"[http] {response.status} {response.reason}")
    body = response.read().decode("utf-8", errors="replace")
    print(body[:120])
    connection.close()


def run_ftp(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        print("[ftp]", sock.recv(4096).decode("utf-8", errors="replace").strip())
        for command in ("USER demo\r\n", "PASS demo\r\n", "LIST\r\n", "QUIT\r\n"):
            sock.sendall(command.encode("utf-8"))
            time.sleep(0.2)
            print("[ftp]", sock.recv(4096).decode("utf-8", errors="replace").strip())


def _read_smtp_reply(sock: socket.socket) -> str:
    """Read one SMTP reply, joining multiline continuations into a single line."""
    reply = ""
    while True:
        try:
            chunk = sock.recv(4096).decode("utf-8", errors="replace")
        except TimeoutError:
            break
        if not chunk:
            break
        reply += chunk
        final_line = reply.strip().rsplit("\n", 1)[-1]
        if len(final_line) < 4 or final_line[3] != "-":
            break
    return reply.strip().replace("\r\n", " | ").replace("\n", " | ")


def run_smtp(host: str, port: int) -> None:
    with socket.create_connection((host, port), timeout=5) as sock:
        print("[smtp]", _read_smtp_reply(sock))
        # Only protocol-defined reply points expect a response; the mail body
        # stays silent until the terminating "." line ends the DATA phase.
        commands = [
            ("EHLO demo.local\r\n", True),
            ("MAIL FROM:<analyst@example.com>\r\n", True),
            ("RCPT TO:<admin@example.com>\r\n", True),
            ("DATA\r\n", True),
            ("Subject: release note\r\n", False),
            ("SentinelMesh demo message\r\n", False),
            (".\r\n", True),
            ("QUIT\r\n", True),
        ]
        for command, expect_reply in commands:
            sock.sendall(command.encode("utf-8"))
            time.sleep(0.2)
            if not expect_reply:
                continue
            data = _read_smtp_reply(sock)
            if data:
                print("[smtp]", data)


def _detect_ssh_mode(host: str, port: int) -> str:
    """Probe the decoy: real SSH servers stay silent after the banner,
    while the pseudo-SSH fallback sends a plaintext "login as:" prompt."""
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(1.5)
        try:
            data = sock.recv(4096).decode("utf-8", errors="replace")
        except (TimeoutError, ConnectionError):
            data = ""
    return "fake" if "login as:" in data else "real"


def run_real_ssh(host: str, port: int) -> None:
    try:
        import asyncssh
    except ImportError:
        print("[ssh] real-SSH decoy detected; install asyncssh for the interactive demo")
        return

    async def _session() -> None:
        async with asyncssh.connect(
            host,
            port=port,
            username="demo",
            password="demo",
            known_hosts=None,
        ) as connection:
            process = await connection.create_process()
            try:
                banner = await asyncio.wait_for(process.stdout.read(4096), timeout=3)
                if banner.strip():
                    print("[ssh]", banner.strip().splitlines()[0])
                for command in ("whoami", "pwd", "ls", "exit"):
                    process.stdin.write(command + "\n")
                    output = await asyncio.wait_for(process.stdout.read(4096), timeout=3)
                    if output.strip():
                        print("[ssh]", output.strip())
            except (TimeoutError, asyncssh.Error, ConnectionError):
                pass

    asyncio.run(_session())


def run_ssh(host: str, port: int) -> None:
    if _detect_ssh_mode(host, port) == "real":
        run_real_ssh(host, port)
        return
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.settimeout(3)
        banner = sock.recv(4096).decode("utf-8", errors="replace")
        print("[ssh]", banner.strip())
        for command in ("demo\r\n", "demo\r\n", "whoami\r\n", "pwd\r\n", "ls\r\n", "exit\r\n"):
            sock.sendall(command.encode("utf-8"))
            time.sleep(0.25)
            try:
                data = sock.recv(4096).decode("utf-8", errors="replace")
                if data.strip():
                    print("[ssh]", data.strip())
            except (TimeoutError, ConnectionError):
                continue


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local demo traffic for SentinelMesh")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--ftp-port", type=int, default=2121)
    parser.add_argument("--smtp-port", type=int, default=2525)
    parser.add_argument("--ssh-port", type=int, default=2222)
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("demo_local.py only targets localhost for safe demo use")

    run_http(args.host, args.http_port)
    run_ftp(args.host, args.ftp_port)
    run_smtp(args.host, args.smtp_port)
    run_ssh(args.host, args.ssh_port)
    print("Local demo traffic completed.")


if __name__ == "__main__":
    main()
