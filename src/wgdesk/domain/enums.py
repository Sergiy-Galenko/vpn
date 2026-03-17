from __future__ import annotations

from enum import StrEnum


class ServerMode(StrEnum):
    LOCAL = "local"
    SSH = "ssh"


class AuthMethod(StrEnum):
    NONE = "none"
    SSH_KEY = "ssh_key"
    PASSWORD = "password"


class SudoMode(StrEnum):
    NONE = "none"
    SUDO_NOPASSWD = "sudo_nopasswd"
    SUDO_PASSWORD = "sudo_password"


class ClientStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    EXPIRED = "expired"
    DELETED = "deleted"
    IMPORTED_UNKNOWN = "imported_unknown"
    PENDING_DISTRIBUTION = "pending_distribution"


class ActionResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    WARNING = "warning"


class SeverityLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class FirewallBackend(StrEnum):
    UFW = "ufw"
    NFTABLES = "nftables"
    UNKNOWN = "unknown"


class TargetType(StrEnum):
    SERVER = "server"
    CLIENT = "client"
    BACKUP = "backup"
    IMPORT = "import"
    SESSION = "session"

