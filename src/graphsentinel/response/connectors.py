"""Connectors: turn a response action into a concrete command, and maybe run it.

Each connector covers one system -- the directory, the network, the endpoint
agent, or the platform's own monitoring -- and knows how to express each
action it supports as a :class:`Command` with a revert where one exists. The
command goes to a :class:`Backend`, which is the only thing that ever touches
the outside world. The default backend touches nothing.

Why plans are first-class
-------------------------
An operator reviewing an incident needs to see *exactly* what would run:
``Disable-ADAccount -Identity 'U66@DOM1'`` is reviewable, "lock the account"
is not. So every connector produces the literal command even in dry-run, and
the record keeps it. It also means a connector can be tested to the character
without any directory present.

Session invalidation, honestly
------------------------------
``force_reauth`` is the one disruptive action the response layer runs
unattended, and it is worth being precise about what it can and cannot do
on-premises. Logging the account off its sessions on the source host and
revoking cloud refresh tokens are both achievable and reversible. Invalidating
already-issued on-premises Kerberos tickets is not achievable without changing
the account's key -- which is a credential reset, irreversible, and gated
behind approval. The command plan does what can be done reversibly and the
limitation is recorded on the result, so nobody reads "sessions invalidated"
and assumes the tickets are dead.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Literal, Protocol

from graphsentinel.detection.response import ACTIONS

CommandKind = Literal["powershell", "http", "internal"]
Status = Literal["dry_run", "executed", "failed", "unsupported"]


@dataclass(frozen=True, slots=True)
class Target:
    """What an action is aimed at. Names, never dictionary indices."""

    account: str | None = None
    host: str | None = None
    source_host: str | None = None
    destination_host: str | None = None

    def describe(self) -> str:
        parts = [
            f"{k}={v}"
            for k, v in (
                ("account", self.account),
                ("host", self.host),
                ("source_host", self.source_host),
                ("destination_host", self.destination_host),
            )
            if v
        ]
        return ", ".join(parts) or "(no target)"


@dataclass(frozen=True, slots=True)
class Command:
    kind: CommandKind
    text: str
    description: str
    revert: Command | None = None
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "text": self.text,
            "description": self.description,
            "revert": self.revert.to_dict() if self.revert else None,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    action: str
    target: Target
    status: Status
    command: Command | None
    output: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "target": self.target.describe(),
            "status": self.status,
            "command": self.command.to_dict() if self.command else None,
            "output": self.output,
            "error": self.error,
        }


class Backend(Protocol):
    """The one seam between a command plan and the world."""

    armed: bool

    def run(self, command: Command) -> tuple[Status, str, str]:
        """Return (status, stdout, stderr). Never raise for a failed command."""


@dataclass
class DryRunBackend:
    """Records the plan and performs nothing. The default everywhere."""

    armed: bool = False
    planned: list[Command] = field(default_factory=list)

    def run(self, command: Command) -> tuple[Status, str, str]:
        self.planned.append(command)
        return "dry_run", "", ""


@dataclass
class PowerShellBackend:
    """Executes PowerShell command text. Constructed deliberately, never by default.

    Not validated against a live domain in this environment; correct by
    specification only. A deployment that arms this has decided, with the
    plans in front of it, that they are right for its estate.
    """

    armed: bool = False
    executable: str = "powershell"
    timeout_seconds: int = 60

    def run(self, command: Command) -> tuple[Status, str, str]:
        if not self.armed:
            return "dry_run", "", ""
        if command.kind != "powershell":
            return "unsupported", "", f"cannot run a {command.kind} command"
        try:
            completed = subprocess.run(
                [self.executable, "-NoProfile", "-NonInteractive", "-Command", command.text],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return "failed", "", str(error)
        status: Status = "executed" if completed.returncode == 0 else "failed"
        return status, completed.stdout, completed.stderr


def _ps(value: str) -> str:
    """Quote for PowerShell single-quoted strings."""
    return "'" + value.replace("'", "''") + "'"


class Connector(Protocol):
    name: str
    actions: frozenset[str]

    def plan(self, action: str, target: Target) -> Command: ...


@dataclass
class DirectoryConnector:
    """Active Directory via the ActiveDirectory PowerShell module."""

    name: str = "directory"
    actions: frozenset[str] = frozenset(
        {
            "force_reauth",
            "lock_account",
            "disable_service_account",
            "reset_credentials",
        }
    )

    _TICKET_LIMITATION = (
        "Issued on-premises Kerberos tickets remain valid until they expire; "
        "invalidating them requires a credential reset, which is irreversible "
        "and gated behind approval."
    )

    def plan(self, action: str, target: Target) -> Command:
        if action == "force_reauth":
            return self._force_reauth(target)
        if not target.account:
            raise ValueError(f"{action} needs an account")
        account = _ps(target.account)
        if action in {"lock_account", "disable_service_account"}:
            return Command(
                kind="powershell",
                text=f"Disable-ADAccount -Identity {account}",
                description=f"Disable {target.account}",
                revert=Command(
                    "powershell",
                    f"Enable-ADAccount -Identity {account}",
                    f"Re-enable {target.account}",
                ),
            )
        if action == "reset_credentials":
            return Command(
                kind="powershell",
                text=(
                    f"Set-ADAccountPassword -Identity {account} -Reset -NewPassword "
                    f"(ConvertTo-SecureString -AsPlainText ([System.Web.Security.Membership]"
                    f"::GeneratePassword(24, 4)) -Force); "
                    f"Set-ADUser -Identity {account} -ChangePasswordAtLogon $true"
                ),
                description=f"Rotate the credential for {target.account}",
                limitations=("Irreversible: the previous secret cannot be restored.",),
            )
        raise ValueError(f"{self.name} does not handle {action}")

    def _force_reauth(self, target: Target) -> Command:
        """Session invalidation, scoped to whatever the target names.

        An account target logs that account off the source host and revokes
        its cloud refresh tokens. A host-only target -- the containment
        playbook run against a workstation -- logs *every* interactive session
        off that host, which is what "force re-authentication" means for a
        machine: everyone on it signs in again. Both are reversible by the
        user simply authenticating.
        """
        host = target.source_host or target.host
        if target.account:
            account = _ps(target.account)
            logoff = ""
            if host:
                logoff = (
                    f"Invoke-Command -ComputerName {_ps(host)} -ScriptBlock {{ "
                    f"query user | Select-String {account} | ForEach-Object {{ "
                    f"($_ -split '\\s+')[2] }} | ForEach-Object {{ logoff $_ }} }}; "
                )
            return Command(
                kind="powershell",
                text=logoff + f"Revoke-MgUserSignInSession -UserId {account}",
                description=f"Log {target.account} off its sessions and revoke refresh tokens",
                limitations=(self._TICKET_LIMITATION,),
            )
        if host:
            return Command(
                kind="powershell",
                text=(
                    f"Invoke-Command -ComputerName {_ps(host)} -ScriptBlock {{ "
                    f"query user | Select-Object -Skip 1 | ForEach-Object {{ "
                    f"($_ -split '\\s+')[2] }} | ForEach-Object {{ logoff $_ }} }}"
                ),
                description=f"Log every interactive session off {host}",
                limitations=(self._TICKET_LIMITATION,),
            )
        raise ValueError("force_reauth needs an account or a host")


@dataclass
class NetworkConnector:
    """Host firewall rule on the destination, via remote PowerShell."""

    name: str = "network"
    actions: frozenset[str] = frozenset({"block_network_path"})
    rule_prefix: str = "GraphSentinel"

    def plan(self, action: str, target: Target) -> Command:
        if action != "block_network_path":
            raise ValueError(f"{self.name} does not handle {action}")
        if not (target.source_host and target.destination_host):
            raise ValueError("block_network_path needs a source and a destination host")
        rule = _ps(f"{self.rule_prefix}-block-{target.source_host}")
        destination = _ps(target.destination_host)
        source = _ps(target.source_host)
        return Command(
            kind="powershell",
            text=(
                f"Invoke-Command -ComputerName {destination} -ScriptBlock {{ "
                f"New-NetFirewallRule -DisplayName {rule} -Direction Inbound "
                f"-RemoteAddress (Resolve-DnsName {source}).IPAddress -Action Block }}"
            ),
            description=(
                f"Block {target.source_host} -> {target.destination_host} at the destination"
            ),
            revert=Command(
                "powershell",
                f"Invoke-Command -ComputerName {destination} -ScriptBlock {{ "
                f"Remove-NetFirewallRule -DisplayName {rule} }}",
                f"Unblock {target.source_host} -> {target.destination_host}",
            ),
        )


@dataclass
class EndpointConnector:
    """Endpoint isolation through the EDR's API. Vendor endpoint is configured."""

    name: str = "endpoint"
    actions: frozenset[str] = frozenset({"isolate_host"})
    api_base: str = "https://edr.example.invalid/api"

    def plan(self, action: str, target: Target) -> Command:
        if action != "isolate_host":
            raise ValueError(f"{self.name} does not handle {action}")
        if not target.host:
            raise ValueError("isolate_host needs a host")
        return Command(
            kind="http",
            text=f"POST {self.api_base}/machines/{target.host}/isolate "
            f'{{"comment": "GraphSentinel containment", "type": "Full"}}',
            description=f"Isolate {target.host} from the network",
            revert=Command(
                "http",
                f"POST {self.api_base}/machines/{target.host}/unisolate "
                '{"comment": "GraphSentinel release"}',
                f"Release {target.host}",
            ),
        )


@dataclass
class MonitoringConnector:
    """Actions the platform performs on itself; never leave the process."""

    name: str = "monitoring"
    actions: frozenset[str] = frozenset({"increase_monitoring", "notify_soc"})

    def plan(self, action: str, target: Target) -> Command:
        if action not in self.actions:
            raise ValueError(f"{self.name} does not handle {action}")
        return Command(
            kind="internal",
            text=f"{action}({target.describe()})",
            description=(
                "Raise sampling and retention"
                if action == "increase_monitoring"
                else "Route to the analyst queue with evidence"
            ),
            revert=Command("internal", f"undo_{action}({target.describe()})", "Restore defaults"),
        )


@dataclass
class ConnectorRegistry:
    """Which connector serves which action. Every catalogued action must be served."""

    connectors: tuple[Connector, ...] = field(
        default_factory=lambda: (
            MonitoringConnector(),
            DirectoryConnector(),
            NetworkConnector(),
            EndpointConnector(),
        )
    )

    def __post_init__(self) -> None:
        served: dict[str, str] = {}
        for connector in self.connectors:
            for action in connector.actions:
                if action in served:
                    raise ValueError(
                        f"{action} is served by both {served[action]} and {connector.name}"
                    )
                served[action] = connector.name
        missing = set(ACTIONS) - set(served)
        if missing:
            raise ValueError(f"no connector serves: {sorted(missing)}")
        self._by_action = {a: c for c in self.connectors for a in c.actions}

    def for_action(self, action: str) -> Connector:
        try:
            return self._by_action[action]
        except KeyError:
            raise ValueError(f"unknown action {action!r}") from None
