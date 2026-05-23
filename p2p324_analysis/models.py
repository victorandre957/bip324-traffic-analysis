from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Direction(StrEnum):
    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"
    BIDIRECTIONAL = "bidirectional"
    IN = "in"
    OUT = "out"


class TransportProtocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"


Endpoint = tuple[str, int]
FlowKey = tuple[TransportProtocol, Endpoint, Endpoint]


class PassiveEventType(StrEnum):
    BIP324_HANDSHAKE = "bip324_handshake_candidate"
    BLOCK_ARRIVAL = "block_arrival_candidate"
    COMPACT_BLOCK_ARRIVAL = "compact_block_candidate"
    LARGE_TRANSACTION = "large_transaction_candidate"
    PEER_DISCOVERY_RESPONSE = "peer_discovery_response_candidate"


class LogEventType(StrEnum):
    BIP324_HANDSHAKE = "bip324_handshake"
    BIP324_PEER_CONNECTED = "bip324_peer_connected"
    HANDSHAKE_OR_NEGOTIATION_MESSAGE = "handshake_or_negotiation_message"
    BLOCK_MESSAGE = "block_message"
    COMPACT_BLOCK_MESSAGE = "compact_block_message"
    BLOCK_RECEIVED = "block_received"
    BLOCK_REQUEST = "block_request"
    BLOCK_CREATED = "block_created"
    CHAIN_TIP_UPDATED = "chain_tip_updated"
    TX_OR_RELAY_MESSAGE = "tx_or_relay_message"
    PEER_DISCOVERY_MESSAGE = "peer_discovery_message"
    P2P_MESSAGE = "p2p_message"


class IpIdentityKind(StrEnum):
    POD = "pod"
    SERVICE = "service"


class IpIdentityRole(StrEnum):
    BITCOIN_MINER = "bitcoin-miner"
    BITCOIN_NODE = "bitcoin-node"
    NOISE = "noise"
    SNIFFER = "sniffer"


class StrictModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)


class MutableModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)


class PacketRecord(StrictModel):
    index: int
    timestamp: float
    captured_len: int
    original_len: int
    link_type: int
    protocol: TransportProtocol
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_total_len: int
    transport_payload_len: int
    tcp_flags: int = 0
    captured_payload_prefix: bytes = b""

    @property
    def src(self) -> Endpoint:
        return (self.src_ip, self.src_port)

    @property
    def dst(self) -> Endpoint:
        return (self.dst_ip, self.dst_port)


class Flow(MutableModel):
    key: FlowKey
    packets: list[PacketRecord] = Field(default_factory=list)

    @property
    def protocol(self) -> TransportProtocol:
        return self.key[0]

    @property
    def endpoint_a(self) -> Endpoint:
        return self.key[1]

    @property
    def endpoint_b(self) -> Endpoint:
        return self.key[2]

    @property
    def start_time(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def end_time(self) -> float:
        return self.packets[-1].timestamp if self.packets else 0.0

    def direction(self, packet: PacketRecord) -> Direction:
        return Direction.A_TO_B if packet.src == self.endpoint_a else Direction.B_TO_A

    def payload_packets(self) -> list[PacketRecord]:
        return [packet for packet in self.packets if packet.transport_payload_len > 0]


class FlowFeatures(StrictModel):
    dataset: str
    flow_id: str
    key: FlowKey
    start_time: float
    end_time: float
    duration_seconds: float
    packet_count: int
    payload_packet_count: int
    bytes_total: int
    bytes_a_to_b: int
    bytes_b_to_a: int
    first_payload_a_to_b: int
    first_payload_b_to_a: int
    initial_flight_a_to_b: int
    initial_flight_b_to_a: int
    estimated_handshake_garbage_a_to_b: int | None
    estimated_handshake_garbage_b_to_a: int | None
    entropy_first_payloads: float
    cleartext_hint: str | None
    bip324_transport_is_tcp: bool
    bip324_has_enough_payload_packets: bool
    bip324_first_initial_flight_in_range: bool
    bip324_second_initial_flight_in_range: bool
    bip324_initial_flights_balanced: bool
    bip324_entropy_is_high: bool
    bip324_has_no_cleartext_hint: bool
    bip324_has_active_payload_exchange: bool
    bip324_requirements_met: int
    bip324_requirements_total: int
    bitcoin_v2_candidate: bool
    notes: list[str] = Field(default_factory=list)


class PassiveEvent(StrictModel):
    dataset: str
    flow_id: str
    timestamp: float
    event_type: PassiveEventType
    signal_strength: float
    direction: Direction
    observed_bytes: int
    window_seconds: float
    details: dict[str, Any] = Field(default_factory=dict)


class LogEvent(StrictModel):
    dataset: str
    node: str
    timestamp: float
    event_type: LogEventType
    direction: Direction | None
    message_type: str | None
    message_size: int | None
    peer_id: int | None
    peer_addr: str | None
    raw: str


class EvaluationRow(StrictModel):
    dataset: str
    event_type: PassiveEventType
    label: str
    predicted_count: int
    ground_truth_count: int
    true_positive: int
    false_positive: int
    false_negative: int
    detector_error_count: int
    precision: float
    recall: float
    f1: float
    miss_rate: float
    false_alarm_rate: float
    matching_window_seconds: float
    validation_start_time: float | None = None
    validation_end_time: float | None = None


class FalsePositiveEvent(StrictModel):
    dataset: str
    event_type: PassiveEventType
    flow_id: str
    timestamp: float
    direction: Direction
    observed_bytes: int
    signal_strength: float
    reason: str
    confused_with_noise: str | None = None
    possible_confusion_reason: str | None = None
    matching_window_seconds: float
    endpoint_a_ip: str
    endpoint_a_port: int
    endpoint_a_name: str | None = None
    endpoint_a_role: IpIdentityRole | None = None
    endpoint_b_ip: str
    endpoint_b_port: int
    endpoint_b_name: str | None = None
    endpoint_b_role: IpIdentityRole | None = None


class IpIdentity(StrictModel):
    ip: str
    name: str
    kind: IpIdentityKind
    role: IpIdentityRole | None = None


class PassiveAnalysisConfig(StrictModel):
    dataset: str
    flow_window_seconds: float = Field(default=1.0, gt=0)
    block_arrival_min_bytes: int | None = Field(default=None, ge=0)
    compact_block_min_bytes: int | None = Field(default=None, ge=0)
    large_transaction_min_bytes: int | None = Field(default=None, ge=0)
    peer_discovery_min_bytes: int | None = Field(default=None, ge=0)
    peer_discovery_max_elapsed_seconds: float | None = Field(default=15.0, gt=0)
    bip324_required_checks: int = Field(default=5, ge=1)
    bip324_ellswift_bytes: int = Field(default=64, gt=0)
    bip324_max_garbage_bytes: int = Field(default=4095, ge=0)


class DatasetSummary(StrictModel):
    name: str
    analysis_profile: str = "warnet"
    pcap_path: str
    log_paths: list[str]
    ip_map_path: str | None
    metadata_path: str | None = None
    simulation_seed: str | None = None
    validation_available: bool
    flow_count: int
    candidate_flow_count: int
    passive_event_count: int
    log_event_count: int
    false_positive_event_count: int = 0
    block_arrival_min_bytes: int | None = None
    compact_block_min_bytes: int | None = None
    large_transaction_min_bytes: int | None = None
    peer_discovery_min_bytes: int | None = None
    pcap_start_time: float | None = None
    pcap_end_time: float | None = None
    log_start_time: float | None = None
    log_end_time: float | None = None
    validation_start_time: float | None = None
    validation_end_time: float | None = None
