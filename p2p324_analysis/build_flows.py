import hashlib
from collections import OrderedDict
from collections.abc import Iterable

from .models import Endpoint, Flow, FlowKey, PacketRecord, TransportProtocol


class BidirectionalFlowBuilder:
    def build(self, packets: Iterable[PacketRecord]) -> list[Flow]:
        flows: OrderedDict[FlowKey, Flow] = OrderedDict()
        for packet in packets:
            key = self._flow_key(packet.protocol, packet.src, packet.dst)
            if key not in flows:
                flows[key] = Flow(key=key)
            flows[key].packets.append(packet)
        return list(flows.values())

    @staticmethod
    def flow_id(key: FlowKey) -> str:
        raw = f"{key[0]}|{key[1][0]}:{key[1][1]}|{key[2][0]}:{key[2][1]}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def _flow_key(protocol: TransportProtocol, src: Endpoint, dst: Endpoint) -> FlowKey:
        return (protocol, src, dst) if src <= dst else (protocol, dst, src)
