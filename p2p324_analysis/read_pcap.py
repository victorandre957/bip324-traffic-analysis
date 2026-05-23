import ipaddress
import struct
from pathlib import Path
from typing import Iterator

from .models import PacketRecord, TransportProtocol


DLT_EN10MB = 1
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


class PcapFormatError(ValueError):
    pass


class PcapFileReader:
    def __init__(self, path: str | Path, ignore_truncated_tail: bool = True) -> None:
        self.path = Path(path)
        self.ignore_truncated_tail = ignore_truncated_tail

    def packets(self) -> Iterator[PacketRecord]:
        with self.path.open("rb") as file_obj:
            header = file_obj.read(24)
            if len(header) != 24:
                raise PcapFormatError(f"{self.path} is too small to be a pcap")

            endian, ts_scale = self._parse_magic(header[:4])
            magic, version_major, version_minor, _tz, _sigfigs, _snaplen, link_type = struct.unpack(
                f"{endian}IHHIIII", header
            )
            if version_major != 2 or version_minor != 4:
                raise PcapFormatError(f"unsupported pcap version {version_major}.{version_minor}")

            packet_index = 0
            while True:
                packet_header = file_obj.read(16)
                if not packet_header:
                    break
                if len(packet_header) != 16:
                    if self.ignore_truncated_tail:
                        break
                    raise PcapFormatError(f"truncated packet header in {self.path}")

                ts_sec, ts_frac, captured_len, original_len = struct.unpack(f"{endian}IIII", packet_header)
                packet_data = file_obj.read(captured_len)
                if len(packet_data) != captured_len:
                    if self.ignore_truncated_tail:
                        break
                    raise PcapFormatError(f"truncated packet data in {self.path}")

                timestamp = ts_sec + (ts_frac / ts_scale)
                parsed = self._parse_packet(packet_index, timestamp, captured_len, original_len, link_type, packet_data)
                packet_index += 1
                if parsed is not None:
                    yield parsed

    @staticmethod
    def _parse_magic(raw_magic: bytes) -> tuple[str, float]:
        if raw_magic == b"\xd4\xc3\xb2\xa1":
            return "<", 1_000_000.0
        if raw_magic == b"\xa1\xb2\xc3\xd4":
            return ">", 1_000_000.0
        if raw_magic == b"\x4d\x3c\xb2\xa1":
            return "<", 1_000_000_000.0
        if raw_magic == b"\xa1\xb2\x3c\x4d":
            return ">", 1_000_000_000.0
        raise PcapFormatError(f"unsupported pcap magic {raw_magic.hex()}")

    def _parse_packet(
        self,
        index: int,
        timestamp: float,
        captured_len: int,
        original_len: int,
        link_type: int,
        data: bytes,
    ) -> PacketRecord | None:
        ethertype, offset = self._link_payload(link_type, data)
        if ethertype == ETHERTYPE_IPV4:
            return self._parse_ipv4(index, timestamp, captured_len, original_len, link_type, data[offset:])
        if ethertype == ETHERTYPE_IPV6:
            return self._parse_ipv6(index, timestamp, captured_len, original_len, link_type, data[offset:])
        return None

    @staticmethod
    def _link_payload(link_type: int, data: bytes) -> tuple[int, int]:
        if link_type == DLT_EN10MB:
            if len(data) < 14:
                return 0, 0
            return struct.unpack("!H", data[12:14])[0], 14
        if link_type == DLT_LINUX_SLL:
            if len(data) < 16:
                return 0, 0
            return struct.unpack("!H", data[14:16])[0], 16
        if link_type == DLT_LINUX_SLL2:
            if len(data) < 20:
                return 0, 0
            return struct.unpack("!H", data[0:2])[0], 20
        return 0, 0

    @staticmethod
    def _parse_ipv4(
        index: int,
        timestamp: float,
        captured_len: int,
        original_len: int,
        link_type: int,
        data: bytes,
    ) -> PacketRecord | None:
        if len(data) < 20:
            return None
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or ihl < 20 or len(data) < ihl:
            return None
        ip_total_len = struct.unpack("!H", data[2:4])[0]
        protocol_num = data[9]
        src_ip = str(ipaddress.IPv4Address(data[12:16]))
        dst_ip = str(ipaddress.IPv4Address(data[16:20]))
        transport = data[ihl:]
        return PcapFileReader._parse_transport(
            index,
            timestamp,
            captured_len,
            original_len,
            link_type,
            TransportProtocol.TCP if protocol_num == 6 else TransportProtocol.UDP if protocol_num == 17 else None,
            src_ip,
            dst_ip,
            ip_total_len,
            ihl,
            transport,
        )

    @staticmethod
    def _parse_ipv6(
        index: int,
        timestamp: float,
        captured_len: int,
        original_len: int,
        link_type: int,
        data: bytes,
    ) -> PacketRecord | None:
        if len(data) < 40 or data[0] >> 4 != 6:
            return None
        payload_len = struct.unpack("!H", data[4:6])[0]
        next_header = data[6]
        src_ip = str(ipaddress.IPv6Address(data[8:24]))
        dst_ip = str(ipaddress.IPv6Address(data[24:40]))
        transport = data[40:]
        return PcapFileReader._parse_transport(
            index,
            timestamp,
            captured_len,
            original_len,
            link_type,
            TransportProtocol.TCP if next_header == 6 else TransportProtocol.UDP if next_header == 17 else None,
            src_ip,
            dst_ip,
            payload_len + 40,
            40,
            transport,
        )

    @staticmethod
    def _parse_transport(
        index: int,
        timestamp: float,
        captured_len: int,
        original_len: int,
        link_type: int,
        protocol: TransportProtocol | None,
        src_ip: str,
        dst_ip: str,
        ip_total_len: int,
        ip_header_len: int,
        transport: bytes,
    ) -> PacketRecord | None:
        if protocol == TransportProtocol.TCP:
            if len(transport) < 20:
                return None
            src_port, dst_port = struct.unpack("!HH", transport[:4])
            data_offset = (transport[12] >> 4) * 4
            if data_offset < 20:
                return None
            flags = transport[13]
            payload_len = max(0, ip_total_len - ip_header_len - data_offset)
            prefix = transport[data_offset : data_offset + min(64, max(0, len(transport) - data_offset))]
        elif protocol == TransportProtocol.UDP:
            if len(transport) < 8:
                return None
            src_port, dst_port, udp_len = struct.unpack("!HHH", transport[:6])
            flags = 0
            payload_len = max(0, udp_len - 8)
            prefix = transport[8 : 8 + min(64, max(0, len(transport) - 8))]
        else:
            return None

        return PacketRecord(
            index=index,
            timestamp=timestamp,
            captured_len=captured_len,
            original_len=original_len,
            link_type=link_type,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ip_total_len=ip_total_len,
            transport_payload_len=payload_len,
            tcp_flags=flags,
            captured_payload_prefix=prefix,
        )
