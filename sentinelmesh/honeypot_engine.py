from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from sentinelmesh.config import Settings
from sentinelmesh.deception_ai import AdaptiveDeceptionEngine
from sentinelmesh.intel_engine import ThreatIntelCorrelator
from sentinelmesh.models import AttackSession, EventRecord, EventType, ObservedCommand, utc_now
from sentinelmesh.profiler import AttackProfiler
from sentinelmesh.reporter import ReportGenerator
from sentinelmesh.storage import EventStore

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class SessionContext:
    session: AttackSession
    prompt: str


class HoneypotEngine:
    def __init__(
        self,
        settings: Settings,
        store: EventStore,
        profiler: AttackProfiler,
        correlator: ThreatIntelCorrelator,
        reporter: ReportGenerator,
        deception_engine: AdaptiveDeceptionEngine,
    ) -> None:
        self.settings = settings
        self.store = store
        self.profiler = profiler
        self.correlator = correlator
        self.reporter = reporter
        self.deception_engine = deception_engine
        self.active_sessions: dict[str, SessionContext] = {}
        self._servers: list[asyncio.AbstractServer] = []
        self._logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )

    async def start(self) -> None:
        if self.settings.enable_http:
            self._servers.append(
                await asyncio.start_server(
                    self._handle_http,
                    self.settings.listen_host,
                    self.settings.http_port,
                )
            )
        if self.settings.enable_ftp:
            self._servers.append(
                await asyncio.start_server(
                    self._handle_ftp,
                    self.settings.listen_host,
                    self.settings.ftp_port,
                )
            )
        if self.settings.enable_smtp:
            self._servers.append(
                await asyncio.start_server(
                    self._handle_smtp,
                    self.settings.listen_host,
                    self.settings.smtp_port,
                )
            )
        if self.settings.enable_ssh:
            await self._start_ssh()

        bound: list[tuple[str, int]] = []
        for server in self._servers:
            if hasattr(server, "sockets"):
                for sock in server.sockets or []:
                    try:
                        bound.append(sock.getsockname())
                    except OSError as exc:
                        self._logger.debug(
                            "Unable to determine bound address for socket: %s",
                            exc,
                        )
        self._logger.info(
            "SentinelMesh honeypot services listening on %s", bound
        )

    async def serve_forever(self) -> None:
        await self.start()
        await asyncio.gather(*(server.serve_forever() for server in self._servers))

    def shutdown_sync(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            for session_id in list(self.active_sessions):
                try:
                    loop.run_until_complete(self._close_session(session_id))
                except Exception:
                    self._logger.exception("error closing session %s", session_id)
            for server in self._servers:
                try:
                    server.close()
                except Exception:
                    self._logger.exception("error closing server during shutdown")
            try:
                results = loop.run_until_complete(
                    asyncio.gather(
                        *(server.wait_closed() for server in self._servers),
                        return_exceptions=True,
                    )
                )
                for result in results:
                    if isinstance(result, Exception):
                        self._logger.warning(
                            "error waiting for server shutdown: %s",
                            result,
                        )
            except Exception:
                self._logger.exception("error waiting for servers to close")
        finally:
            try:
                loop.close()
            except Exception:
                self._logger.exception("error closing shutdown event loop")

    async def _start_ssh(self) -> None:
        try:
            import asyncssh

            await self._ensure_host_key_async(asyncssh)

            class SentinelSSHServer(asyncssh.SSHServer):
                def __init__(self, engine: HoneypotEngine) -> None:
                    self.engine = engine
                    self.connection: asyncssh.SSHServerConnection | None = None

                def connection_made(self, connection: asyncssh.SSHServerConnection) -> None:
                    self.connection = connection
                    peer_ip, peer_port = connection.get_extra_info("peername")[:2]
                    self.peer_ip = str(peer_ip)
                    self.peer_port = int(peer_port)

                def begin_auth(self, username: str) -> bool:
                    self.username = username
                    return True

                def password_auth_supported(self) -> bool:
                    return True

                def validate_password(self, username: str, password: str) -> bool:
                    self.validated_username = username
                    self.validated_password = password
                    return True

            async def process_handler(process: asyncssh.SSHServerProcess[Any]) -> None:
                connection = process.get_extra_info("connection")
                server = connection.get_owner() if connection is not None else None
                session_id, prompt = await self._open_session(
                    service="ssh",
                    remote_ip=getattr(server, "peer_ip", "unknown"),
                    remote_port=getattr(server, "peer_port", 0),
                    local_port=self.settings.ssh_port,
                )
                try:
                    context = self.active_sessions[session_id]
                    context.session.credentials["username"] = getattr(
                        server, "validated_username", "root"
                    )
                    context.session.credentials["password"] = getattr(
                        server, "validated_password", "toor"
                    )
                    self.store.upsert_session(context.session)
                    process.stdout.write("Ubuntu 24.04.1 LTS\r\n")
                    process.stdout.write(prompt)
                    async for raw_line in process.stdin:
                        command = raw_line.strip()
                        if not command:
                            process.stdout.write(prompt)
                            continue
                        try:
                            response = await self._handle_shell_command(
                                session_id, command
                            )
                        except Exception:
                            self._logger.exception(
                                "shell command handling failed for %s", session_id
                            )
                            response = ""
                        process.stdout.write(f"{response}\r\n" if response else "")
                        if command in {"exit", "logout", "quit"}:
                            break
                        process.stdout.write(
                            self.deception_engine.get_prompt(session_id)
                        )
                finally:
                    await self._close_session(session_id)

            server = await asyncssh.create_server(
                lambda: SentinelSSHServer(self),
                self.settings.listen_host,
                self.settings.ssh_port,
                server_host_keys=[str(self.settings.host_key_path)],
                process_factory=process_handler,
                encoding="utf-8",
            )
            self._servers.append(server)
            self._logger.info(
                "real SSH deception service enabled on port %s",
                self.settings.ssh_port,
            )
        except Exception as exc:
            self._logger.warning(
                "falling back to pseudo-SSH decoy on port %s: %s",
                self.settings.ssh_port,
                exc,
            )
            self._servers.append(
                await asyncio.start_server(
                    self._handle_fake_ssh,
                    self.settings.listen_host,
                    self.settings.ssh_port,
                )
            )

    async def _ensure_host_key_async(self, asyncssh_module: Any) -> None:
        if self.settings.host_key_path.exists():
            return
        try:
            key = asyncssh_module.generate_private_key("ssh-rsa")
            key.write_private_key(str(self.settings.host_key_path))
        except Exception as exc:
            LOGGER.warning("failed to generate SSH host key: %s", exc)
            raise

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        session_id, _ = await self._open_session(
            "http", str(peer_ip), int(peer_port), self.settings.http_port
        )
        try:
            try:
                data = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=8
                )
            except Exception:
                data = await reader.read(4096)

            request_text = data.decode("utf-8", errors="replace")
            await self._record_message(session_id, request_text)

            # Keep the decoy believable but generic enough to remain reusable.
            body = (
                "<html><head><title>Sign In :: Backup Admin</title></head><body>"
                "<h1>Admin Console</h1>"
                "<p>Maintenance window scheduled. Authentication required.</p>"
                "</body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: nginx/1.24.0\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "Connection: close\r\n\r\n"
                f"{body}"
            )
            writer.write(response.encode("utf-8"))
            await writer.drain()
            self._increment_sent(session_id, len(response.encode("utf-8")))
        except Exception:
            self._logger.exception("HTTP session handling failed for %s", session_id)
        finally:
            try:
                writer.close()
            except Exception:
                self._logger.exception("error closing HTTP writer for %s", session_id)
            await self._close_session(session_id)

    async def _handle_ftp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        session_id, _ = await self._open_session(
            "ftp", str(peer_ip), int(peer_port), self.settings.ftp_port
        )
        try:
            await self._write_line(writer, "220 (vsFTPd 3.0.5)")
            username = "anonymous"
            while not reader.at_eof():
                raw = await reader.readline()
                if not raw:
                    break
                command = raw.decode("utf-8", errors="replace").strip()
                if not command:
                    continue
                await self._record_message(session_id, command)
                upper = command.upper()
                if upper.startswith("USER "):
                    username = command[5:].strip() or "anonymous"
                    self.active_sessions[session_id].session.credentials[
                        "username"
                    ] = username
                    await self._write_line(writer, "331 Please specify the password.")
                elif upper.startswith("PASS "):
                    self.active_sessions[session_id].session.credentials[
                        "password"
                    ] = command[5:].strip()
                    await self._write_line(writer, "230 Login successful.")
                elif upper == "SYST":
                    await self._write_line(writer, "215 UNIX Type: L8")
                elif upper in {"PWD", "XPWD"}:
                    await self._write_line(
                        writer, '257 "/var/backups" is the current directory'
                    )
                elif upper.startswith("LIST"):
                    await self._write_line(
                        writer, "150 Here comes the directory listing."
                    )
                    await self._write_line(
                        writer,
                        "-rw-r--r-- 1 root root 4096 Mar 13 08:02 backup_2024.zip",
                    )
                    await self._write_line(
                        writer,
                        "drwxr-xr-x 2 root root 4096 Apr 01 12:40 uploads",
                    )
                    await self._write_line(writer, "226 Directory send OK.")
                elif upper == "QUIT":
                    await self._write_line(writer, "221 Goodbye.")
                    break
                else:
                    await self._write_line(
                        writer, f"200 Command okay for {username}."
                    )
        except Exception:
            self._logger.exception("FTP session handling failed for %s", session_id)
        finally:
            try:
                writer.close()
            except Exception:
                self._logger.exception(
                    "error closing FTP writer for %s", session_id
                )
            await self._close_session(session_id)

    async def _handle_smtp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        session_id, _ = await self._open_session(
            "smtp", str(peer_ip), int(peer_port), self.settings.smtp_port
        )
        try:
            await self._write_line(writer, "220 mx1.corp-mail.local ESMTP Postfix")
            data_mode = False
            message_lines: list[str] = []
            while not reader.at_eof():
                raw = await reader.readline()
                if not raw:
                    break
                command = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not command:
                    continue
                await self._record_message(session_id, command)
                if data_mode:
                    if command == ".":
                        data_mode = False
                        await self._write_line(
                            writer, "250 2.0.0 Ok: queued as 51BAA"
                        )
                        if message_lines:
                            self.active_sessions[session_id].session.message_samples.extend(
                                message_lines[:4]
                            )
                        message_lines.clear()
                        continue
                    message_lines.append(command)
                    continue
                upper = command.upper()
                if upper.startswith(("EHLO", "HELO")):
                    await self._write_line(writer, "250-mx1.corp-mail.local")
                    await self._write_line(writer, "250-PIPELINING")
                    await self._write_line(writer, "250 AUTH LOGIN PLAIN")
                elif upper.startswith("MAIL FROM"):
                    await self._write_line(writer, "250 2.1.0 Ok")
                elif upper.startswith("RCPT TO"):
                    await self._write_line(writer, "250 2.1.5 Ok")
                elif upper == "DATA":
                    data_mode = True
                    await self._write_line(
                        writer, "354 End data with <CR><LF>.<CR><LF>"
                    )
                elif upper == "QUIT":
                    await self._write_line(writer, "221 2.0.0 Bye")
                    break
                else:
                    await self._write_line(writer, "250 2.0.0 Ok")
        except Exception:
            self._logger.exception("SMTP session handling failed for %s", session_id)
        finally:
            try:
                writer.close()
            except Exception:
                self._logger.exception(
                    "error closing SMTP writer for %s", session_id
                )
            await self._close_session(session_id)

    async def _handle_fake_ssh(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer_ip, peer_port = writer.get_extra_info("peername")[:2]
        session_id, prompt = await self._open_session(
            "ssh", str(peer_ip), int(peer_port), self.settings.ssh_port
        )
        try:
            await self._write_line(
                writer, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
            )
            await self._write_line(writer, "login as:")
            username_line = await reader.readline()
            username = (
                username_line.decode("utf-8", errors="replace").strip() or "root"
            )
            self.active_sessions[session_id].session.credentials["username"] = (
                username
            )
            await self._write_line(writer, "password:")
            password_line = await reader.readline()
            password = (
                password_line.decode("utf-8", errors="replace").strip() or "toor"
            )
            self.active_sessions[session_id].session.credentials["password"] = (
                password
            )
            self.store.upsert_session(
                self.active_sessions[session_id].session
            )
            await self._write_line(writer, "Ubuntu 24.04.1 LTS")
            writer.write(prompt.encode("utf-8"))
            await writer.drain()
            while not reader.at_eof():
                raw = await reader.readline()
                if not raw:
                    break
                command = raw.decode("utf-8", errors="replace").strip()
                if not command:
                    continue
                try:
                    response = await self._handle_shell_command(
                        session_id, command
                    )
                except Exception:
                    self._logger.exception(
                        "fake-SSH shell command handling failed for %s",
                        session_id,
                    )
                    response = ""
                if response:
                    await self._write_line(writer, response)
                if command in {"exit", "logout", "quit"}:
                    break
                writer.write(
                    self.deception_engine.get_prompt(session_id).encode("utf-8")
                )
                await writer.drain()
        except Exception:
            self._logger.exception(
                "fake-SSH session handling failed for %s", session_id
            )
        finally:
            try:
                writer.close()
            except Exception:
                self._logger.exception(
                    "error closing fake-SSH writer for %s", session_id
                )
            await self._close_session(session_id)

    async def _handle_shell_command(self, session_id: str, command: str) -> str:
        context = self.active_sessions[session_id]
        session = context.session
        session.command_history.append(command)
        self.store.append_command(
            ObservedCommand(
                session_id=session_id, command=command, observed_at=utc_now()
            )
        )
        self.store.append_event(
            EventRecord(
                event_type=EventType.COMMAND_OBSERVED,
                occurred_at=utc_now(),
                session_id=session_id,
                payload={"command": command},
            )
        )
        self.store.upsert_session(session)
        return self.deception_engine.synthesize_response(
            session_id, command, session.command_history
        )

    async def _open_session(
        self,
        service: str,
        remote_ip: str,
        remote_port: int,
        local_port: int,
    ) -> tuple[str, str]:
        session_id = str(uuid.uuid4())
        session = AttackSession(
            session_id=session_id,
            service=service,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            started_at=utc_now(),
        )
        prompt = self.deception_engine.get_prompt(session_id)
        self.active_sessions[session_id] = SessionContext(
            session=session, prompt=prompt
        )
        self.store.upsert_session(session)
        self.store.append_event(
            EventRecord(
                event_type=EventType.CONNECTION_OPENED,
                occurred_at=utc_now(),
                session_id=session_id,
                payload={
                    "service": service,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                },
            )
        )
        return session_id, prompt

    async def _close_session(self, session_id: str) -> None:
        context = self.active_sessions.pop(session_id, None)
        if context is None:
            return
        session = context.session
        session.ended_at = utc_now()
        try:
            commands = self.store.list_commands_for_session(session_id)
            profile = self.profiler.build_profile(session, commands)
            session.threat_id = profile.threat_id
            session.threat_score = profile.risk_score
            try:
                hits = await self.correlator.lookup_ip(session.remote_ip)
            except Exception:
                self._logger.exception(
                    "intel lookup failed for %s", session.remote_ip
                )
                hits = []
            stix_bundle = self.correlator.build_stix_bundle(
                session, profile, hits
            )
            stem = f"{session.started_at.strftime('%Y%m%dT%H%M%S')}_{profile.threat_id[:12]}"
            try:
                self.reporter.write_json(
                    stem, session, profile, hits, stix_bundle
                )
                self.reporter.write_pdf(stem, session, profile, hits)
            except Exception:
                self._logger.exception("report generation failed for %s", session_id)
            self.store.save_profile(profile)
            self.store.upsert_session(session)
            self.store.append_event(
                EventRecord(
                    event_type=EventType.CONNECTION_CLOSED,
                    occurred_at=utc_now(),
                    session_id=session_id,
                    payload={
                        "service": session.service,
                        "risk_score": profile.risk_score,
                    },
                )
            )
            self.store.append_event(
                EventRecord(
                    event_type=EventType.PROFILE_CREATED,
                    occurred_at=utc_now(),
                    session_id=session_id,
                    payload={
                        "threat_id": profile.threat_id,
                        "labels": profile.labels,
                    },
                )
            )
            if hits:
                self.store.append_event(
                    EventRecord(
                        event_type=EventType.INTEL_CORRELATED,
                        occurred_at=utc_now(),
                        session_id=session_id,
                        payload={"providers": [hit.provider for hit in hits]},
                    )
                )
            self.store.append_event(
                EventRecord(
                    event_type=EventType.REPORT_GENERATED,
                    occurred_at=utc_now(),
                    session_id=session_id,
                    payload={
                        "threat_id": profile.threat_id,
                        "report_stem": stem,
                    },
                )
            )
        except Exception:
            self._logger.exception("session finalization failed for %s", session_id)

    async def _record_message(self, session_id: str, message: str) -> None:
        session = self.active_sessions[session_id].session
        session.message_samples.append(message[:240])
        session.bytes_received += len(message.encode("utf-8", errors="ignore"))
        self.store.upsert_session(session)

    def _increment_sent(self, session_id: str, byte_count: int) -> None:
        session = self.active_sessions[session_id].session
        session.bytes_sent += byte_count
        self.store.upsert_session(session)

    async def _write_line(self, writer: asyncio.StreamWriter, line: str) -> None:
        payload = f"{line}\r\n".encode()
        writer.write(payload)
        await writer.drain()

