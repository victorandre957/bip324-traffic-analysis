import json
from pathlib import Path
from typing import Any
from collections import Counter, defaultdict
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from .build_flows import BidirectionalFlowBuilder
from .detect_passive import PassiveMetadataDetector
from .models import (
    DatasetSummary,
    Direction,
    EvaluationRow,
    FalsePositiveEvent,
    Flow,
    FlowFeatures,
    IpIdentity,
    IpIdentityRole,
    LogEvent,
    LogEventType,
    PacketRecord,
    PassiveEvent,
)
from .read_bitcoin_logs import BitcoinCoreLogReader
from .read_ip_map import WarnetIpMapReader
from .read_pcap import PcapFileReader
from .validate_predictions import PredictionValidator
from .write_reports import ReportWriter


class DatasetConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    pcap_path: Path
    log_paths: list[Path]
    ip_map_path: Path | None = None
    metadata_path: Path | None = None
    analysis_profile: str = "warnet"


class DatasetResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    config: DatasetConfig
    flow_features: list[FlowFeatures]
    passive_events: list[PassiveEvent]
    log_events: list[LogEvent]
    evaluation: list[EvaluationRow]
    false_positive_events: list[FalsePositiveEvent]
    ip_identities: dict[str, IpIdentity]
    metadata: dict[str, Any] = Field(default_factory=dict)
    pcap_start_time: float | None = None
    pcap_end_time: float | None = None
    log_start_time: float | None = None
    log_end_time: float | None = None
    validation_start_time: float | None = None
    validation_end_time: float | None = None
    block_arrival_min_bytes: int | None = None
    compact_block_min_bytes: int | None = None
    large_transaction_min_bytes: int | None = None
    peer_discovery_min_bytes: int | None = None


class AnalysisPipeline:
    def __init__(self, output_dir: str | Path = "results") -> None:
        self.output_dir = Path(output_dir)

    def run(self, datasets: list[DatasetConfig]) -> list[DatasetResult]:
        results = [self.run_dataset(config) for config in datasets]
        self.export(results)
        return results

    def run_dataset(self, config: DatasetConfig) -> DatasetResult:
        packets = self._read_packets(config)
        pcap_start, pcap_end = self._time_bounds(packets)
        ip_identities = WarnetIpMapReader().parse(config.ip_map_path)
        scoped_flows = self._build_scoped_flows(packets, ip_identities)
        log_events = BitcoinCoreLogReader().parse_many(config.name, config.log_paths)
        block_arrival_min_bytes = self._average_incoming_block_size(log_events)
        compact_block_min_bytes = self._average_message_size(log_events, "cmpctblock")
        large_transaction_min_bytes = self._large_transaction_min_bytes(log_events, config.analysis_profile)
        peer_discovery_min_bytes = self._peer_discovery_min_bytes(log_events, config.analysis_profile)
        features, passive_events = self._detect_passive_events(
            config.name,
            config.analysis_profile,
            scoped_flows,
            block_arrival_min_bytes,
            compact_block_min_bytes,
            large_transaction_min_bytes,
            peer_discovery_min_bytes,
        )
        log_start, log_end = self._time_bounds(log_events)
        validation_start, validation_end = self._overlap_window(pcap_start, pcap_end, log_start, log_end)
        metadata = self._read_metadata(config.metadata_path)
        bitcoin_flow_ids = self._bitcoin_flow_ids(features, ip_identities) if ip_identities else None
        evaluator = PredictionValidator(config.analysis_profile)
        evaluation, false_positive_events = self._validate_passive_events(
            evaluator,
            config.name,
            passive_events,
            log_events,
            features,
            ip_identities,
            bitcoin_flow_ids,
            validation_start,
            validation_end,
            large_transaction_min_bytes,
        )
        return DatasetResult(
            config=config,
            flow_features=features,
            passive_events=passive_events,
            log_events=log_events,
            evaluation=evaluation,
            false_positive_events=false_positive_events,
            ip_identities=ip_identities,
            metadata=metadata,
            pcap_start_time=pcap_start,
            pcap_end_time=pcap_end,
            log_start_time=log_start,
            log_end_time=log_end,
            validation_start_time=validation_start,
            validation_end_time=validation_end,
            block_arrival_min_bytes=block_arrival_min_bytes,
            compact_block_min_bytes=compact_block_min_bytes,
            large_transaction_min_bytes=large_transaction_min_bytes,
            peer_discovery_min_bytes=peer_discovery_min_bytes,
        )

    @staticmethod
    def _read_packets(config: DatasetConfig) -> list[PacketRecord]:
        return list(PcapFileReader(config.pcap_path).packets())

    @classmethod
    def _build_scoped_flows(
        cls,
        packets: list[PacketRecord],
        ip_identities: dict[str, IpIdentity],
    ) -> list[Flow]:
        flows = BidirectionalFlowBuilder().build(packets)
        return cls._scope_flows_to_lab(flows, ip_identities)

    @staticmethod
    def _detect_passive_events(
        dataset: str,
        analysis_profile: str,
        flows: list[Flow],
        block_arrival_min_bytes: int | None,
        compact_block_min_bytes: int | None,
        large_transaction_min_bytes: int | None,
        peer_discovery_min_bytes: int | None,
    ) -> tuple[list[FlowFeatures], list[PassiveEvent]]:
        return PassiveMetadataDetector(
            dataset,
            block_arrival_min_bytes=block_arrival_min_bytes,
            compact_block_min_bytes=compact_block_min_bytes,
            large_transaction_min_bytes=large_transaction_min_bytes,
            peer_discovery_min_bytes=peer_discovery_min_bytes,
            peer_discovery_max_elapsed_seconds=None if analysis_profile == "mainnet" else 15.0,
        ).analyze(flows)

    @classmethod
    def _validate_passive_events(
        cls,
        validator: PredictionValidator,
        dataset: str,
        passive_events: list[PassiveEvent],
        log_events: list[LogEvent],
        features: list[FlowFeatures],
        ip_identities: dict[str, IpIdentity],
        bitcoin_flow_ids: set[str] | None,
        validation_start: float | None,
        validation_end: float | None,
        large_transaction_min_bytes: int | None,
    ) -> tuple[list[EvaluationRow], list[FalsePositiveEvent]]:
        if not log_events or validation_start is None or validation_end is None:
            return [], []
        evaluation = validator.evaluate(
            dataset,
            passive_events,
            log_events,
            bitcoin_flow_ids,
            validation_start,
            validation_end,
            large_transaction_min_bytes,
        )
        false_positive_events = cls._false_positive_events(
            validator,
            passive_events,
            log_events,
            features,
            ip_identities,
            bitcoin_flow_ids,
            validation_start,
            validation_end,
            large_transaction_min_bytes,
        )
        return evaluation, false_positive_events

    @staticmethod
    def _scope_flows_to_lab(flows: list[Flow], ip_identities: dict[str, IpIdentity]) -> list[Flow]:
        if not ip_identities:
            return flows
        scoped: list[Flow] = []
        for flow in flows:
            endpoint_a_ip = flow.key[1][0]
            endpoint_b_ip = flow.key[2][0]
            identity_a = ip_identities.get(endpoint_a_ip)
            identity_b = ip_identities.get(endpoint_b_ip)
            if identity_a is None or identity_b is None:
                continue
            if identity_a.role == IpIdentityRole.SNIFFER or identity_b.role == IpIdentityRole.SNIFFER:
                continue
            scoped.append(flow)
        return scoped

    @staticmethod
    def _average_incoming_block_size(events: list[LogEvent]) -> int | None:
        sizes = [
            event.message_size
            for event in events
            if event.event_type in {LogEventType.BLOCK_MESSAGE, LogEventType.COMPACT_BLOCK_MESSAGE}
            and event.direction == Direction.IN
            and event.message_size is not None
        ]
        if not sizes:
            return None
        return max(1, round(sum(sizes) / len(sizes)))

    @staticmethod
    def _average_message_size(events: list[LogEvent], message_type: str) -> int | None:
        sizes = [
            event.message_size
            for event in events
            if event.message_type == message_type
            and event.message_size is not None
            and event.message_size > 0
        ]
        if not sizes:
            return None
        return max(1, round(sum(sizes) / len(sizes)))

    @staticmethod
    def _large_transaction_min_bytes(events: list[LogEvent], analysis_profile: str) -> int | None:
        sizes = sorted(
            event.message_size
            for event in events
            if event.message_type == "tx"
            and event.message_size is not None
        )
        if not sizes:
            return None
        quantile = 0.99 if analysis_profile == "mainnet" else 0.9
        return AnalysisPipeline._percentile(sizes, quantile)

    @staticmethod
    def _peer_discovery_min_bytes(events: list[LogEvent], analysis_profile: str) -> int | None:
        sizes = sorted(
            event.message_size
            for event in events
            if event.message_type == "addrv2"
            and event.message_size is not None
            and event.message_size > 0
        )
        if not sizes:
            return None
        if analysis_profile == "mainnet":
            return AnalysisPipeline._percentile(sizes, 0.95)
        return max(1, round(sum(sizes) / len(sizes)))

    @staticmethod
    def _percentile(values: list[int], quantile: float) -> int:
        index = max(0, min(len(values) - 1, round((len(values) - 1) * quantile)))
        return values[index]

    def export(self, results: list[DatasetResult]) -> None:
        exporter = ReportWriter(self.output_dir)
        all_features = [feature for result in results for feature in result.flow_features]
        all_events = [event for result in results for event in result.passive_events]
        all_logs = [event for result in results for event in result.log_events]
        all_eval = [row for result in results for row in result.evaluation]
        all_false_positives = [event for result in results for event in result.false_positive_events]

        exporter.write_csv("flow_features.csv", all_features)
        exporter.write_csv("passive_events.csv", all_events)
        exporter.write_csv("log_events.csv", all_logs)
        exporter.write_csv("evaluation.csv", all_eval)
        exporter.write_csv("false_positive_events.csv", all_false_positives)
        exporter.write_json(
            "summary.json",
            {
                "datasets": [self._summary_for_result(result) for result in results]
            },
        )
        self._export_notebook_tables(exporter, results)

    @staticmethod
    def _export_notebook_tables(exporter: ReportWriter, results: list[DatasetResult]) -> None:
        summaries = [AnalysisPipeline._summary_for_result(result) for result in results]
        exporter.write_csv(
            "notebook_dataset_scope.csv",
            summaries,
            fieldnames=[
                "name",
                "analysis_profile",
                "flow_count",
                "candidate_flow_count",
                "passive_event_count",
                "log_event_count",
                "false_positive_event_count",
                "simulation_seed",
                "block_arrival_min_bytes",
                "compact_block_min_bytes",
                "large_transaction_min_bytes",
                "peer_discovery_min_bytes",
            ],
        )
        exporter.write_csv(
            "notebook_validation.csv",
            [
                {
                    "dataset": row.dataset,
                    "event": AnalysisPipeline._event_label(row.event_type),
                    "predicted": row.predicted_count,
                    "ground_truth": row.ground_truth_count,
                    "true_positive": row.true_positive,
                    "false_positive": row.false_positive,
                    "false_negative": row.false_negative,
                    "precision": row.precision,
                    "recall": row.recall,
                    "f1": row.f1,
                }
                for result in results
                for row in result.evaluation
            ],
            fieldnames=[
                "dataset",
                "event",
                "predicted",
                "ground_truth",
                "true_positive",
                "false_positive",
                "false_negative",
                "precision",
                "recall",
                "f1",
            ],
        )
        exporter.write_csv(
            "notebook_block_arrival_comparison.csv",
            [
                {
                    "dataset": row.dataset,
                    "mode": row.label,
                    "predicted": row.predicted_count,
                    "ground_truth": row.ground_truth_count,
                    "true_positive": row.true_positive,
                    "false_positive": row.false_positive,
                    "false_negative": row.false_negative,
                    "precision": row.precision,
                    "recall": row.recall,
                    "f1": row.f1,
                    "matching_window_seconds": row.matching_window_seconds,
                }
                for result in results
                for row in PredictionValidator(result.config.analysis_profile).block_arrival_comparison(
                    result.config.name,
                    result.passive_events,
                    result.log_events,
                    result.validation_start_time,
                    result.validation_end_time,
                )
            ],
            fieldnames=[
                "dataset",
                "mode",
                "predicted",
                "ground_truth",
                "true_positive",
                "false_positive",
                "false_negative",
                "precision",
                "recall",
                "f1",
                "matching_window_seconds",
            ],
        )
        exporter.write_csv(
            "notebook_false_positive_noise.csv",
            AnalysisPipeline._false_positive_noise_summary(results),
            fieldnames=["dataset", "event", "confused_with", "possible_reason", "count"],
        )
        exporter.write_csv(
            "notebook_passive_summary.csv",
            AnalysisPipeline._passive_summary(results),
            fieldnames=["dataset", "event", "count"],
        )
        exporter.write_csv(
            "notebook_passive_timeseries.csv",
            AnalysisPipeline._passive_timeseries(results),
            fieldnames=["dataset", "event", "seconds_from_start", "count"],
        )
        exporter.write_csv(
            "notebook_bip324_candidates.csv",
            [
                {
                    "dataset": feature.dataset,
                    "flow_id": feature.flow_id,
                    "packet_count": feature.packet_count,
                    "payload_packet_count": feature.payload_packet_count,
                    "bip324_requirements_met": feature.bip324_requirements_met,
                    "bip324_requirements_total": feature.bip324_requirements_total,
                    "first_initial_flight_in_range": feature.bip324_first_initial_flight_in_range,
                    "second_initial_flight_in_range": feature.bip324_second_initial_flight_in_range,
                    "initial_flights_balanced": feature.bip324_initial_flights_balanced,
                    "entropy_is_high": feature.bip324_entropy_is_high,
                    "has_no_cleartext_hint": feature.bip324_has_no_cleartext_hint,
                    "endpoint_a": f"{feature.key[1][0]}:{feature.key[1][1]}",
                    "endpoint_b": f"{feature.key[2][0]}:{feature.key[2][1]}",
                }
                for result in results
                for feature in result.flow_features
                if feature.bitcoin_v2_candidate
            ],
            fieldnames=[
                "dataset",
                "flow_id",
                "packet_count",
                "payload_packet_count",
                "bip324_requirements_met",
                "bip324_requirements_total",
                "first_initial_flight_in_range",
                "second_initial_flight_in_range",
                "initial_flights_balanced",
                "entropy_is_high",
                "has_no_cleartext_hint",
                "endpoint_a",
                "endpoint_b",
            ],
        )

    @staticmethod
    def _false_positive_noise_summary(results: list[DatasetResult]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for result in results:
            detailed = AnalysisPipeline._false_positive_detail_counts(result)
            for evaluation in result.evaluation:
                remaining = evaluation.false_positive
                if remaining <= 0:
                    continue
                event = AnalysisPipeline._event_label(evaluation.event_type)
                entries = detailed.get(event) or [(
                    "unknown",
                    "False positives were counted by validation, but no detailed example was available.",
                    remaining,
                )]
                for target, reason, count in entries[:3]:
                    if remaining <= 0:
                        break
                    displayed_count = min(count, remaining)
                    rows.append({
                        "dataset": result.config.name,
                        "event": event,
                        "confused_with": target,
                        "possible_reason": reason,
                        "count": displayed_count,
                    })
                    remaining -= displayed_count
        if rows:
            return rows
        return [
            {
                "dataset": result.config.name,
                "event": "No false positives",
                "confused_with": "none",
                "possible_reason": "No false-positive events in this dataset.",
                "count": 0,
            }
            for result in results
        ]

    @staticmethod
    def _false_positive_detail_counts(result: DatasetResult) -> dict[str, list[tuple[str, str, int]]]:
        counts = Counter(
            (
                AnalysisPipeline._event_label(event.event_type),
                AnalysisPipeline._confusion_target(event),
                event.possible_confusion_reason,
            )
            for event in result.false_positive_events
        )
        grouped: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
        for (event, target, reason), count in counts.most_common():
            grouped[event].append((target, reason, count))
        return grouped

    @staticmethod
    def _confusion_target(event: FalsePositiveEvent) -> str:
        if event.confused_with_noise:
            return event.confused_with_noise
        roles = {
            str(role)
            for role in (event.endpoint_a_role, event.endpoint_b_role)
            if role is not None
        }
        names = {
            name
            for name in (event.endpoint_a_name, event.endpoint_b_name)
            if name
        }
        if any("bitcoin" in role for role in roles):
            return "Bitcoin flow without matching log event"
        if names:
            return " + ".join(sorted(names))
        return "unknown or external flow"

    @staticmethod
    def _passive_summary(results: list[DatasetResult]) -> list[dict[str, Any]]:
        counts = Counter(
            (event.dataset, AnalysisPipeline._event_label(event.event_type))
            for result in results
            for event in result.passive_events
            if AnalysisPipeline._in_validation_window(event.timestamp, result)
        )
        return [
            {"dataset": dataset, "event": event, "count": count}
            for (dataset, event), count in counts.most_common()
        ]

    @staticmethod
    def _passive_timeseries(results: list[DatasetResult], bin_seconds: int = 30) -> list[dict[str, Any]]:
        bins: dict[tuple[str, str, int], int] = defaultdict(int)
        starts = {result.config.name: result.validation_start_time or result.pcap_start_time or 0.0 for result in results}
        for result in results:
            start = starts[result.config.name]
            for event in result.passive_events:
                if not AnalysisPipeline._in_validation_window(event.timestamp, result):
                    continue
                bin_index = int((event.timestamp - start) // bin_seconds)
                bins[(event.dataset, AnalysisPipeline._event_label(event.event_type), bin_index)] += 1
        return [
            {
                "dataset": dataset,
                "event": event,
                "seconds_from_start": bin_index * bin_seconds,
                "count": count,
            }
            for (dataset, event, bin_index), count in sorted(bins.items())
        ]

    @staticmethod
    def _event_label(event_type: str) -> str:
        return {
            "bip324_handshake_candidate": "BIP324 handshake",
            "block_arrival_candidate": "Block arrival",
            "compact_block_candidate": "Compact block arrival",
            "large_transaction_candidate": "Large transaction",
            "peer_discovery_response_candidate": "Address response",
        }.get(str(event_type), str(event_type))

    @staticmethod
    def _in_validation_window(timestamp: float, result: DatasetResult) -> bool:
        start = result.validation_start_time
        end = result.validation_end_time
        if start is None or end is None:
            return True
        return start <= timestamp <= end

    @staticmethod
    def _iso_time(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, tz=UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _false_positive_events(
        evaluator: PredictionValidator,
        passive_events: list[PassiveEvent],
        log_events: list[LogEvent],
        features: list[FlowFeatures],
        ip_identities: dict[str, IpIdentity],
        bitcoin_flow_ids: set[str] | None,
        validation_start: float | None,
        validation_end: float | None,
        large_transaction_min_bytes: int | None,
    ) -> list[FalsePositiveEvent]:
        features_by_flow_id = {feature.flow_id: feature for feature in features}
        rows: list[FalsePositiveEvent] = []
        for event, reason, window in evaluator.false_positive_predictions(
            passive_events,
            log_events,
            bitcoin_flow_ids,
            validation_start,
            validation_end,
            large_transaction_min_bytes,
        ):
            feature = features_by_flow_id.get(event.flow_id)
            if feature is None:
                continue
            endpoint_a = feature.key[1]
            endpoint_b = feature.key[2]
            identity_a = ip_identities.get(endpoint_a[0])
            identity_b = ip_identities.get(endpoint_b[0])
            confused_with_noise = AnalysisPipeline._confused_with_noise(identity_a, identity_b)
            rows.append(
                FalsePositiveEvent(
                    dataset=event.dataset,
                    event_type=event.event_type,
                    flow_id=event.flow_id,
                    timestamp=event.timestamp,
                    direction=event.direction,
                    observed_bytes=event.observed_bytes,
                    signal_strength=event.signal_strength,
                    reason=reason,
                    confused_with_noise=confused_with_noise,
                    possible_confusion_reason=AnalysisPipeline._possible_confusion_reason(
                        event.event_type,
                        reason,
                        confused_with_noise,
                    ),
                    matching_window_seconds=window,
                    endpoint_a_ip=endpoint_a[0],
                    endpoint_a_port=endpoint_a[1],
                    endpoint_a_name=identity_a.name if identity_a else None,
                    endpoint_a_role=identity_a.role if identity_a else None,
                    endpoint_b_ip=endpoint_b[0],
                    endpoint_b_port=endpoint_b[1],
                    endpoint_b_name=identity_b.name if identity_b else None,
                    endpoint_b_role=identity_b.role if identity_b else None,
                )
            )
        return rows

    @staticmethod
    def _confused_with_noise(identity_a: IpIdentity | None, identity_b: IpIdentity | None) -> str | None:
        labels = {
            AnalysisPipeline._noise_label(identity)
            for identity in (identity_a, identity_b)
            if identity and identity.role == IpIdentityRole.NOISE
        }
        labels.discard(None)
        if not labels:
            return None
        return " + ".join(sorted(labels))

    @staticmethod
    def _noise_label(identity: IpIdentity | None) -> str | None:
        if identity is None:
            return None
        name = identity.name.lower()
        if "tor" in name:
            return "Tor noise"
        if "torrent" in name:
            return "BitTorrent noise"
        if "https" in name:
            return "HTTPS noise"
        if "noise-client" in name or "noise-server" in name:
            return "HTTP noise"
        if "http" in name:
            return "HTTP noise"
        if "streaming" in name:
            return "streaming noise"
        if identity.role == IpIdentityRole.NOISE:
            return "unclassified noise"
        return None

    @staticmethod
    def _possible_confusion_reason(
        event_type: str,
        reason: str,
        confused_with_noise: str | None,
    ) -> str:
        if confused_with_noise:
            if event_type == "bip324_handshake_candidate":
                return "encrypted session setup matched the BIP324 handshake-size pattern"
            if event_type == "block_arrival_candidate":
                return "noise burst crossed the block-arrival byte threshold"
            if event_type == "compact_block_candidate":
                return "noise burst had a compact-block-like size"
            if event_type == "large_transaction_candidate":
                return "noise burst matched the run-specific large-transaction byte range"
            if event_type == "peer_discovery_response_candidate":
                return "small early-session burst matched an address-response pattern"
            return "non-Bitcoin noise matched a passive detector heuristic"
        if reason == "no_ground_truth_match_in_window":
            return "Bitcoin-shaped traffic had no matching Bitcoin Core log event in the validation window"
        return "non-Bitcoin flow matched a passive detector heuristic"

    @staticmethod
    def _summary_for_result(result: DatasetResult) -> DatasetSummary:
        return DatasetSummary(
            name=result.config.name,
            analysis_profile=result.config.analysis_profile,
            pcap_path=str(result.config.pcap_path),
            log_paths=[str(path) for path in result.config.log_paths],
            ip_map_path=str(result.config.ip_map_path) if result.config.ip_map_path else None,
            metadata_path=str(result.config.metadata_path) if result.config.metadata_path else None,
            simulation_seed=AnalysisPipeline._metadata_seed(result.metadata),
            validation_available=bool(result.log_events),
            flow_count=len(result.flow_features),
            candidate_flow_count=sum(1 for item in result.flow_features if item.bitcoin_v2_candidate),
            passive_event_count=len(result.passive_events),
            log_event_count=len(result.log_events),
            false_positive_event_count=len(result.false_positive_events),
            block_arrival_min_bytes=result.block_arrival_min_bytes,
            compact_block_min_bytes=result.compact_block_min_bytes,
            large_transaction_min_bytes=result.large_transaction_min_bytes,
            peer_discovery_min_bytes=result.peer_discovery_min_bytes,
            pcap_start_time=result.pcap_start_time,
            pcap_end_time=result.pcap_end_time,
            log_start_time=result.log_start_time,
            log_end_time=result.log_end_time,
            validation_start_time=result.validation_start_time,
            validation_end_time=result.validation_end_time,
        )

    @staticmethod
    def _read_metadata(path: Path | None) -> dict[str, Any]:
        if path is None or not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _metadata_seed(metadata: dict[str, Any]) -> str | None:
        seed = metadata.get("seed")
        return str(seed) if seed is not None else None

    @staticmethod
    def _bitcoin_flow_ids(features: list[FlowFeatures], ip_identities: dict[str, IpIdentity]) -> set[str]:
        flow_ids: set[str] = set()
        bitcoin_roles = {IpIdentityRole.BITCOIN_MINER, IpIdentityRole.BITCOIN_NODE}
        for feature in features:
            endpoint_a = feature.key[1]
            endpoint_b = feature.key[2]
            identities = [ip_identities.get(endpoint_a[0]), ip_identities.get(endpoint_b[0])]
            if any(identity and identity.role in bitcoin_roles for identity in identities):
                flow_ids.add(feature.flow_id)
        return flow_ids

    @staticmethod
    def _time_bounds(items) -> tuple[float | None, float | None]:
        timestamps = [item.timestamp for item in items]
        if not timestamps:
            return None, None
        return min(timestamps), max(timestamps)

    @staticmethod
    def _overlap_window(
        pcap_start: float | None,
        pcap_end: float | None,
        log_start: float | None,
        log_end: float | None,
    ) -> tuple[float | None, float | None]:
        if None in {pcap_start, pcap_end, log_start, log_end}:
            return None, None
        start = max(pcap_start, log_start)
        end = min(pcap_end, log_end)
        if start > end:
            return None, None
        return start, end


def discover_default_datasets(root: str | Path = ".") -> list[DatasetConfig]:
    root = Path(root)
    datasets: list[DatasetConfig] = []

    datasets.extend(discover_warnet_datasets(_default_warnet_dir(root)))
    return datasets


def discover_warnet_datasets(data_dir: str | Path) -> list[DatasetConfig]:
    data_dir = Path(data_dir)
    if not data_dir.exists():
        return []

    run_dirs = sorted(path for path in data_dir.glob("run-*") if path.is_dir())
    if not run_dirs and _pcaps_in(data_dir):
        run_dirs = [data_dir]

    datasets: list[DatasetConfig] = []
    for run_dir in run_dirs:
        pcaps = _pcaps_in(run_dir)
        logs = sorted([*run_dir.glob("*-debug.log"), *run_dir.glob("debug*.log")])
        if not pcaps or not logs:
            continue
        pcap = _preferred_pcap(pcaps)
        ip_map = run_dir / "ip-map.txt"
        metadata = run_dir / "metadata.json"
        datasets.append(
            DatasetConfig(
                name=run_dir.name,
                pcap_path=pcap,
                log_paths=logs,
                ip_map_path=ip_map if ip_map.exists() else None,
                metadata_path=metadata if metadata.exists() else None,
                analysis_profile="warnet",
            )
        )
    return datasets


def discover_directory_datasets(
    data_dir: str | Path,
    pcap_glob: str = "*.pcap",
    log_glob: str = "debug*.log",
    dataset_prefix: str | None = None,
    analysis_profile: str = "warnet",
) -> list[DatasetConfig]:
    data_dir = Path(data_dir)
    pcaps = sorted(data_dir.glob(pcap_glob))
    logs = sorted(data_dir.glob(log_glob)) if log_glob else []
    prefix = dataset_prefix or data_dir.name

    datasets: list[DatasetConfig] = []
    for idx, pcap in enumerate(pcaps, start=1):
        if len(pcaps) == 1:
            paired_logs = logs
            name = prefix
        else:
            paired_logs = _paired_mainnet_logs(pcap, logs)
            name = f"{prefix}-{idx}-{pcap.stem}"
        datasets.append(
            DatasetConfig(
                name=name,
                pcap_path=pcap,
                log_paths=paired_logs,
                ip_map_path=_ip_map_for_pcap(pcap),
                metadata_path=_metadata_for_pcap(pcap),
                analysis_profile=analysis_profile,
            )
        )
    return datasets


def _default_warnet_dir(root: Path) -> Path:
    return root / "data_to_analysis"


def _pcaps_in(directory: Path) -> list[Path]:
    return sorted([*directory.glob("*.pcap"), *directory.glob("*.pcapng")])


def _preferred_pcap(pcaps: list[Path]) -> Path:
    for pcap in pcaps:
        if pcap.name == "isp-capture.pcap":
            return pcap
    return pcaps[0]


def _paired_mainnet_logs(pcap: Path, logs: list[Path]) -> list[Path]:
    if not logs:
        return []
    suffix = pcap.stem.removeprefix("captura_p2p_v2")
    expected = f"debug{suffix}.log" if suffix else "debug.log"
    for log in logs:
        if log.name == expected:
            return [log]
    return []


def _metadata_for_pcap(pcap: Path) -> Path | None:
    metadata = pcap.parent / "metadata.json"
    return metadata if metadata.exists() else None


def _ip_map_for_pcap(pcap: Path) -> Path | None:
    ip_map = pcap.parent / "ip-map.txt"
    return ip_map if ip_map.exists() else None
