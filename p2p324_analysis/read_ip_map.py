import re
from pathlib import Path

from .models import IpIdentity, IpIdentityKind, IpIdentityRole


class WarnetIpMapReader:
    POD_LINE_RE = re.compile(r"^(?P<name>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+")
    SERVICE_LINE_RE = re.compile(
        r"^(?P<name>\S+)\s+ClusterIP\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+<none>\s+(?P<ports>\S+)"
    )

    def parse(self, path: str | Path | None) -> dict[str, IpIdentity]:
        if path is None:
            return {}
        path = Path(path)
        if not path.exists():
            return {}

        identities: dict[str, IpIdentity] = {}
        section: IpIdentityKind | None = None
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() == "PODS":
                section = IpIdentityKind.POD
                continue
            if line.strip() == "SERVICES":
                section = IpIdentityKind.SERVICE
                continue
            if not line or line.startswith("NAME"):
                continue
            if section is None:
                continue
            match = self.POD_LINE_RE.match(line) if section == IpIdentityKind.POD else self.SERVICE_LINE_RE.match(line)
            if not match:
                continue
            name = match.group("name")
            ip = match.group("ip")
            identities[ip] = IpIdentity(ip=ip, name=name, kind=section, role=self._role_for_name(name))
        return identities

    @staticmethod
    def _role_for_name(name: str) -> IpIdentityRole | None:
        if name == "tank-0001":
            return IpIdentityRole.BITCOIN_MINER
        if name.startswith("tank-"):
            return IpIdentityRole.BITCOIN_NODE
        if "noise" in name:
            return IpIdentityRole.NOISE
        if "sniffer" in name:
            return IpIdentityRole.SNIFFER
        return None
