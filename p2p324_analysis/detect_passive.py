import math
from collections import Counter, defaultdict

from .build_flows import BidirectionalFlowBuilder
from .models import (
    Direction,
    Flow,
    FlowFeatures,
    PacketRecord,
    PassiveAnalysisConfig,
    PassiveEvent,
    PassiveEventType,
    TransportProtocol,
)


class PassiveMetadataDetector:
    HIGH_ENTROPY_MIN_BITS = 5.2
    MAX_INITIAL_FLIGHT_RATIO = 8

    def __init__(
        self,
        dataset: str,
        flow_window_seconds: float = 1.0,
        block_arrival_min_bytes: int | None = None,
        compact_block_min_bytes: int | None = None,
        large_transaction_min_bytes: int | None = None,
        peer_discovery_min_bytes: int | None = None,
        peer_discovery_max_elapsed_seconds: float | None = 15.0,
        bip324_required_checks: int = 5,
    ) -> None:
        self.config = PassiveAnalysisConfig(
            dataset=dataset,
            flow_window_seconds=flow_window_seconds,
            block_arrival_min_bytes=block_arrival_min_bytes,
            compact_block_min_bytes=compact_block_min_bytes,
            large_transaction_min_bytes=large_transaction_min_bytes,
            peer_discovery_min_bytes=peer_discovery_min_bytes,
            peer_discovery_max_elapsed_seconds=peer_discovery_max_elapsed_seconds,
            bip324_required_checks=bip324_required_checks,
        )

    def analyze(self, flows: list[Flow]) -> tuple[list[FlowFeatures], list[PassiveEvent]]:
        features = [self.extract_features(flow) for flow in flows]
        candidate_ids = {feature.flow_id for feature in features if feature.bitcoin_v2_candidate}
        events: list[PassiveEvent] = []
        for flow, feature in zip(flows, features):
            if feature.flow_id in candidate_ids:
                events.extend(self.detect_events(flow, feature.flow_id))
        return features, events

    def extract_features(self, flow: Flow) -> FlowFeatures:
        flow_id = BidirectionalFlowBuilder.flow_id(flow.key)
        payload_packets = flow.payload_packets()
        bytes_by_direction: dict[Direction, int] = {Direction.A_TO_B: 0, Direction.B_TO_A: 0}
        first_payload: dict[Direction, int] = {Direction.A_TO_B: 0, Direction.B_TO_A: 0}

        for packet in payload_packets:
            direction = flow.direction(packet)
            bytes_by_direction[direction] += packet.transport_payload_len
            if first_payload[direction] == 0:
                first_payload[direction] = packet.transport_payload_len

        initial_flights = self._initial_flights(flow)
        entropy = self._entropy(b"".join(packet.captured_payload_prefix for packet in payload_packets[:12]))
        cleartext_hint = self._cleartext_hint(payload_packets)
        checks = self._bip324_handshake_checks(flow, initial_flights, entropy, cleartext_hint)
        notes = self._check_notes(checks)
        garbage_a_to_b = self._estimated_handshake_garbage(initial_flights[Direction.A_TO_B])
        garbage_b_to_a = self._estimated_handshake_garbage(initial_flights[Direction.B_TO_A])

        return FlowFeatures(
            dataset=self.config.dataset,
            flow_id=flow_id,
            key=flow.key,
            start_time=flow.start_time,
            end_time=flow.end_time,
            duration_seconds=max(0.0, flow.end_time - flow.start_time),
            packet_count=len(flow.packets),
            payload_packet_count=len(payload_packets),
            bytes_total=bytes_by_direction[Direction.A_TO_B] + bytes_by_direction[Direction.B_TO_A],
            bytes_a_to_b=bytes_by_direction[Direction.A_TO_B],
            bytes_b_to_a=bytes_by_direction[Direction.B_TO_A],
            first_payload_a_to_b=first_payload[Direction.A_TO_B],
            first_payload_b_to_a=first_payload[Direction.B_TO_A],
            initial_flight_a_to_b=initial_flights[Direction.A_TO_B],
            initial_flight_b_to_a=initial_flights[Direction.B_TO_A],
            estimated_handshake_garbage_a_to_b=garbage_a_to_b,
            estimated_handshake_garbage_b_to_a=garbage_b_to_a,
            entropy_first_payloads=entropy,
            cleartext_hint=cleartext_hint,
            bip324_transport_is_tcp=checks["transport_is_tcp"],
            bip324_has_enough_payload_packets=checks["has_enough_payload_packets"],
            bip324_first_initial_flight_in_range=checks["first_initial_flight_in_range"],
            bip324_second_initial_flight_in_range=checks["second_initial_flight_in_range"],
            bip324_initial_flights_balanced=checks["initial_flights_balanced"],
            bip324_entropy_is_high=checks["entropy_is_high"],
            bip324_has_no_cleartext_hint=checks["has_no_cleartext_hint"],
            bip324_has_active_payload_exchange=checks["has_active_payload_exchange"],
            bip324_requirements_met=sum(checks.values()),
            bip324_requirements_total=len(checks),
            bitcoin_v2_candidate=self._is_bip324_candidate(checks),
            notes=notes,
        )

    def detect_events(self, flow: Flow, flow_id: str) -> list[PassiveEvent]:
        payload_packets = flow.payload_packets()
        if not payload_packets:
            return []

        buckets: dict[tuple[int, Direction], int] = defaultdict(int)
        start = flow.start_time
        for packet in payload_packets:
            bucket = int((packet.timestamp - start) / self.config.flow_window_seconds)
            buckets[(bucket, flow.direction(packet))] += packet.transport_payload_len

        block_threshold = self._block_threshold(flow)
        compact_threshold = self._compact_block_threshold()
        large_tx_threshold = self._large_transaction_threshold()
        peer_discovery_threshold = self._peer_discovery_threshold()

        events: list[PassiveEvent] = []
        for (bucket, direction), observed_bytes in sorted(buckets.items()):
            timestamp = start + bucket * self.config.flow_window_seconds
            if observed_bytes >= block_threshold:
                events.append(
                    PassiveEvent(
                        dataset=self.config.dataset,
                        flow_id=flow_id,
                        timestamp=timestamp,
                        event_type=PassiveEventType.BLOCK_ARRIVAL,
                        signal_strength=min(1.0, observed_bytes / max(block_threshold, 1)),
                        direction=direction,
                        observed_bytes=observed_bytes,
                        window_seconds=self.config.flow_window_seconds,
                        details={"threshold": block_threshold},
                    )
                )
            if self._is_compact_block_candidate(observed_bytes, compact_threshold, large_tx_threshold):
                events.append(
                    self._bucket_event(
                        flow_id,
                        timestamp,
                        PassiveEventType.COMPACT_BLOCK_ARRIVAL,
                        direction,
                        observed_bytes,
                        compact_threshold,
                    )
                )
            if self._is_large_transaction_candidate(observed_bytes, large_tx_threshold, timestamp, start):
                events.append(
                    self._bucket_event(
                        flow_id,
                        timestamp,
                        PassiveEventType.LARGE_TRANSACTION,
                        direction,
                        observed_bytes,
                        large_tx_threshold,
                    )
                )
            if self._is_peer_discovery_candidate(observed_bytes, peer_discovery_threshold, timestamp, start):
                events.append(
                    self._bucket_event(
                        flow_id,
                        timestamp,
                        PassiveEventType.PEER_DISCOVERY_RESPONSE,
                        direction,
                        observed_bytes,
                        peer_discovery_threshold,
                    )
                )

        handshake = self._handshake_event(flow, flow_id)
        if handshake is not None:
            events.insert(0, handshake)
        return events

    def _handshake_event(self, flow: Flow, flow_id: str) -> PassiveEvent | None:
        flights = self._initial_flights(flow)
        payload_packets = flow.payload_packets()
        entropy = self._entropy(b"".join(packet.captured_payload_prefix for packet in payload_packets[:12]))
        cleartext_hint = self._cleartext_hint(payload_packets)
        checks = self._bip324_handshake_checks(flow, flights, entropy, cleartext_hint)
        if not self._is_bip324_candidate(checks):
            return None
        first = flights[Direction.A_TO_B]
        second = flights[Direction.B_TO_A]
        complete = checks["first_initial_flight_in_range"] and checks["second_initial_flight_in_range"]
        met = sum(checks.values())
        total = len(checks)
        return PassiveEvent(
            dataset=self.config.dataset,
            flow_id=flow_id,
            timestamp=flow.start_time,
            event_type=PassiveEventType.BIP324_HANDSHAKE,
            signal_strength=met / total,
            direction=Direction.BIDIRECTIONAL,
            observed_bytes=first + second,
            window_seconds=5.0,
            details={
                "requirements": checks,
                "requirements_met": met,
                "requirements_total": total,
                "initial_flight_a_to_b": first,
                "initial_flight_b_to_a": second,
                "ellswift_bytes": self.config.bip324_ellswift_bytes,
                "estimated_garbage_a_to_b": self._estimated_handshake_garbage(first),
                "estimated_garbage_b_to_a": self._estimated_handshake_garbage(second),
                "handshake_visibility": "complete" if complete else "partial_one_direction",
                "inferred_handshake_garbage": "present_or_zero_length_randomized",
            },
        )

    @staticmethod
    def _initial_flights(flow: Flow) -> dict[Direction, int]:
        payload_packets = flow.payload_packets()
        flights = {Direction.A_TO_B: 0, Direction.B_TO_A: 0}
        if not payload_packets:
            return flights

        first_direction = flow.direction(payload_packets[0])
        second_direction = Direction.B_TO_A if first_direction == Direction.A_TO_B else Direction.A_TO_B
        phase = first_direction
        for packet in payload_packets:
            direction = flow.direction(packet)
            if phase == first_direction:
                if direction != first_direction:
                    phase = second_direction
                else:
                    flights[direction] += packet.transport_payload_len
                    continue
            if phase == second_direction:
                if direction != second_direction:
                    break
                flights[direction] += packet.transport_payload_len
        return flights

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())

    @staticmethod
    def _cleartext_hint(payload_packets: list[PacketRecord]) -> str | None:
        prefixes = [packet.captured_payload_prefix for packet in payload_packets[:8] if packet.captured_payload_prefix]
        if not prefixes:
            return None
        first = prefixes[0]
        upper = first[:16].upper()
        if first.startswith(b"\x16\x03"):
            return "tls"
        if upper.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"HTTP/")):
            return "http"
        if first[:4] in (bytes.fromhex("f9beb4d9"), bytes.fromhex("fabfb5da"), bytes.fromhex("0b110907")):
            return "bitcoin_v1_magic"
        ascii_ratio = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in first) / max(len(first), 1)
        if ascii_ratio > 0.85 and len(first) > 12:
            return "mostly_ascii"
        return None

    def _bip324_handshake_checks(
        self,
        flow: Flow,
        flights: dict[Direction, int],
        entropy: float,
        cleartext_hint: str | None,
    ) -> dict[str, bool]:
        first = flights[Direction.A_TO_B]
        second = flights[Direction.B_TO_A]
        both_directions_have_flights = first > 0 and second > 0
        initial_flights_balanced = (
            both_directions_have_flights
            and max(first, second) / max(min(first, second), 1) <= self.MAX_INITIAL_FLIGHT_RATIO
        )
        payload_count = len(flow.payload_packets())
        return {
            "transport_is_tcp": flow.protocol == TransportProtocol.TCP,
            "has_enough_payload_packets": payload_count >= 2,
            "first_initial_flight_in_range": self._bip324_initial_flight_in_range(first),
            "second_initial_flight_in_range": self._bip324_initial_flight_in_range(second),
            "initial_flights_balanced": initial_flights_balanced,
            "entropy_is_high": entropy >= self.HIGH_ENTROPY_MIN_BITS,
            "has_no_cleartext_hint": cleartext_hint is None,
            "has_active_payload_exchange": payload_count >= 5,
        }

    def _is_bip324_candidate(self, checks: dict[str, bool]) -> bool:
        mandatory_checks = (
            checks["transport_is_tcp"],
            checks["has_enough_payload_packets"],
            checks["has_no_cleartext_hint"],
        )
        has_bip324_initial_flight = (
            checks["first_initial_flight_in_range"]
            or checks["second_initial_flight_in_range"]
        )
        return (
            all(mandatory_checks)
            and has_bip324_initial_flight
            and sum(checks.values()) >= self.config.bip324_required_checks
        )

    @staticmethod
    def _check_notes(checks: dict[str, bool]) -> list[str]:
        return [
            f"{name}={'yes' if passed else 'no'}"
            for name, passed in checks.items()
        ]

    def _bip324_initial_flight_in_range(self, size: int) -> bool:
        return (
            self.config.bip324_ellswift_bytes
            <= size
            <= self.config.bip324_ellswift_bytes + self.config.bip324_max_garbage_bytes
        )

    def _estimated_handshake_garbage(self, initial_flight_size: int) -> int | None:
        if not self._bip324_initial_flight_in_range(initial_flight_size):
            return None
        return initial_flight_size - self.config.bip324_ellswift_bytes

    def _block_threshold(self, flow: Flow) -> int:
        if self.config.block_arrival_min_bytes is not None:
            return max(1, self.config.block_arrival_min_bytes)
        total = sum(packet.transport_payload_len for packet in flow.payload_packets())
        if total > 2_000_000:
            return 80_000
        if total > 100_000:
            return 20_000
        return 1500

    def _compact_block_threshold(self) -> int | None:
        if self.config.compact_block_min_bytes is None:
            return None
        return max(1, self.config.compact_block_min_bytes)

    def _large_transaction_threshold(self) -> int | None:
        if self.config.large_transaction_min_bytes is None:
            return None
        return max(1, self.config.large_transaction_min_bytes)

    def _peer_discovery_threshold(self) -> int | None:
        if self.config.peer_discovery_min_bytes is None:
            return None
        return max(1, self.config.peer_discovery_min_bytes)

    def _bucket_event(
        self,
        flow_id: str,
        timestamp: float,
        event_type: PassiveEventType,
        direction: Direction,
        observed_bytes: int,
        threshold: int | None,
    ) -> PassiveEvent:
        threshold = max(1, threshold or observed_bytes)
        return PassiveEvent(
            dataset=self.config.dataset,
            flow_id=flow_id,
            timestamp=timestamp,
            event_type=event_type,
            signal_strength=min(1.0, observed_bytes / threshold),
            direction=direction,
            observed_bytes=observed_bytes,
            window_seconds=self.config.flow_window_seconds,
            details={"threshold": threshold},
        )

    @staticmethod
    def _is_compact_block_candidate(
        observed_bytes: int,
        compact_threshold: int | None,
        large_tx_threshold: int | None,
    ) -> bool:
        if compact_threshold is None:
            return False
        large_tx_upper = compact_threshold * 3
        if large_tx_threshold is not None and large_tx_threshold > compact_threshold:
            large_tx_upper = large_tx_threshold - 1
        upper_bound = min(compact_threshold * 3, large_tx_upper)
        return compact_threshold <= observed_bytes <= upper_bound

    @staticmethod
    def _is_large_transaction_candidate(
        observed_bytes: int,
        large_tx_threshold: int | None,
        timestamp: float,
        flow_start: float,
    ) -> bool:
        if large_tx_threshold is None or timestamp - flow_start < 3.0:
            return False
        return large_tx_threshold <= observed_bytes <= max(large_tx_threshold * 3, large_tx_threshold + 1500)

    def _is_peer_discovery_candidate(
        self,
        observed_bytes: int,
        peer_discovery_threshold: int | None,
        timestamp: float,
        flow_start: float,
    ) -> bool:
        if peer_discovery_threshold is None:
            return False
        elapsed = timestamp - flow_start
        lower_bound = max(20, peer_discovery_threshold)
        upper_bound = max(180, peer_discovery_threshold + 120)
        inside_time_window = elapsed >= 1.0
        if self.config.peer_discovery_max_elapsed_seconds is not None:
            inside_time_window = inside_time_window and elapsed <= self.config.peer_discovery_max_elapsed_seconds
        return inside_time_window and lower_bound <= observed_bytes <= upper_bound
