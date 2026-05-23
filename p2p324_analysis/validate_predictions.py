from collections import defaultdict

from .models import EvaluationRow, LogEvent, LogEventType, PassiveEvent, PassiveEventType


class PredictionValidator:
    LABELS = {
        PassiveEventType.BIP324_HANDSHAKE: "BIP324 handshake",
        PassiveEventType.BLOCK_ARRIVAL: "Block arrival",
        PassiveEventType.COMPACT_BLOCK_ARRIVAL: "Compact block arrival",
        PassiveEventType.LARGE_TRANSACTION: "Large transaction",
        PassiveEventType.PEER_DISCOVERY_RESPONSE: "Address response",
    }
    EVENT_MAP = {
        PassiveEventType.BIP324_HANDSHAKE: {
            LogEventType.BIP324_HANDSHAKE,
            LogEventType.BIP324_PEER_CONNECTED,
        },
        PassiveEventType.BLOCK_ARRIVAL: {
            LogEventType.BLOCK_MESSAGE,
            LogEventType.COMPACT_BLOCK_MESSAGE,
            LogEventType.BLOCK_RECEIVED,
        },
        PassiveEventType.COMPACT_BLOCK_ARRIVAL: {
            LogEventType.COMPACT_BLOCK_MESSAGE,
        },
        PassiveEventType.PEER_DISCOVERY_RESPONSE: {
            LogEventType.PEER_DISCOVERY_MESSAGE,
        },
    }
    WINDOWS = {
        PassiveEventType.BIP324_HANDSHAKE: 5.0,
        PassiveEventType.BLOCK_ARRIVAL: 8.0,
        PassiveEventType.COMPACT_BLOCK_ARRIVAL: 4.0,
        PassiveEventType.LARGE_TRANSACTION: 3.0,
        PassiveEventType.PEER_DISCOVERY_RESPONSE: 3.0,
    }
    BLOCK_TEMPORAL_GROUP_SECONDS = 3.0
    BLOCK_INTERVAL_WINDOW_FRACTION = 0.4
    MAINNET_BLOCK_INTERVAL_SECONDS = 600.0
    MAINNET_BLOCK_INTERVAL_TOLERANCE_SECONDS = 120.0

    def __init__(self, analysis_profile: str = "warnet") -> None:
        self.analysis_profile = analysis_profile

    def evaluate(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        bitcoin_flow_ids: set[str] | None = None,
        validation_start: float | None = None,
        validation_end: float | None = None,
        large_transaction_min_bytes: int | None = None,
    ) -> list[EvaluationRow]:
        truth = self._inside_validation_window(truth, validation_start, validation_end)
        return [
            self._handshake_row(dataset, predictions, truth, bitcoin_flow_ids, validation_start, validation_end),
            self._block_interval_row(dataset, predictions, truth, validation_start, validation_end),
            self._compact_block_row(dataset, predictions, truth, validation_start, validation_end),
            self._large_transaction_row(
                dataset,
                predictions,
                truth,
                large_transaction_min_bytes,
                validation_start,
                validation_end,
            ),
            self._peer_discovery_row(dataset, predictions, truth, validation_start, validation_end),
        ]

    def false_positive_predictions(
        self,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        bitcoin_flow_ids: set[str] | None = None,
        validation_start: float | None = None,
        validation_end: float | None = None,
        large_transaction_min_bytes: int | None = None,
    ) -> list[tuple[PassiveEvent, str, float]]:
        truth = self._inside_validation_window(truth, validation_start, validation_end)
        false_positives: list[tuple[PassiveEvent, str, float]] = []

        handshake_truth = self._handshake_truth(truth)
        handshake_predictions = self._predictions_for_type(
            predictions,
            PassiveEventType.BIP324_HANDSHAKE,
            handshake_truth,
            self.WINDOWS[PassiveEventType.BIP324_HANDSHAKE],
            validation_start,
            validation_end,
        )
        false_positives.extend(
            self._false_positive_matches(
                handshake_predictions,
                handshake_truth,
                self.WINDOWS[PassiveEventType.BIP324_HANDSHAKE],
                bitcoin_flow_ids,
            )
        )

        block_truth = self._profile_block_truth(truth)
        block_predictions, block_window = self._block_interval_predictions(
            predictions,
            block_truth,
            validation_start,
            validation_end,
        )
        false_positives.extend(
            self._false_positive_matches(block_predictions, block_truth, block_window, None)
        )
        false_positives.extend(
            self._generic_false_positive_matches(
                predictions,
                self._compact_block_truth(truth),
                PassiveEventType.COMPACT_BLOCK_ARRIVAL,
                self.WINDOWS[PassiveEventType.COMPACT_BLOCK_ARRIVAL],
                validation_start,
                validation_end,
            )
        )
        false_positives.extend(
            self._generic_false_positive_matches(
                predictions,
                self._large_transaction_truth(truth, large_transaction_min_bytes),
                PassiveEventType.LARGE_TRANSACTION,
                self.WINDOWS[PassiveEventType.LARGE_TRANSACTION],
                validation_start,
                validation_end,
            )
        )
        false_positives.extend(
            self._generic_false_positive_matches(
                predictions,
                self._peer_discovery_truth(truth),
                PassiveEventType.PEER_DISCOVERY_RESPONSE,
                self.WINDOWS[PassiveEventType.PEER_DISCOVERY_RESPONSE],
                validation_start,
                validation_end,
            )
        )
        return false_positives

    def block_arrival_comparison(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        validation_start: float | None = None,
        validation_end: float | None = None,
    ) -> list[EvaluationRow]:
        truth = self._inside_validation_window(truth, validation_start, validation_end)
        block_truth = self._profile_block_truth(truth)
        size_predictions = self._block_size_predictions(predictions, block_truth, validation_start, validation_end)
        interval_predictions, interval_window = self._block_interval_predictions(
            predictions,
            block_truth,
            validation_start,
            validation_end,
        )
        return [
            self._count_row(
                dataset,
                PassiveEventType.BLOCK_ARRIVAL,
                "Block arrival: size only",
                size_predictions,
                block_truth,
                0.0,
                validation_start,
                validation_end,
            ),
            self._count_row(
                dataset,
                PassiveEventType.BLOCK_ARRIVAL,
                "Block arrival: size + interval",
                interval_predictions,
                block_truth,
                interval_window,
                validation_start,
                validation_end,
            ),
        ]

    def _handshake_row(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        bitcoin_flow_ids: set[str] | None,
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        window = self.WINDOWS[PassiveEventType.BIP324_HANDSHAKE]
        ground_truth = self._handshake_truth(truth)
        predicted = self._predictions_for_type(
            predictions,
            PassiveEventType.BIP324_HANDSHAKE,
            ground_truth,
            window,
            validation_start,
            validation_end,
        )
        return self._matching_row(
            dataset,
            PassiveEventType.BIP324_HANDSHAKE,
            self.LABELS[PassiveEventType.BIP324_HANDSHAKE],
            predicted,
            ground_truth,
            window,
            bitcoin_flow_ids,
            validation_start,
            validation_end,
        )

    def _block_interval_row(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        ground_truth = self._profile_block_truth(truth)
        predicted, window = self._block_interval_predictions(
            predictions,
            ground_truth,
            validation_start,
            validation_end,
        )
        return self._count_row(
            dataset,
            PassiveEventType.BLOCK_ARRIVAL,
            self.LABELS[PassiveEventType.BLOCK_ARRIVAL],
            predicted,
            ground_truth,
            window,
            validation_start,
            validation_end,
        )

    def _compact_block_row(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        event_type = PassiveEventType.COMPACT_BLOCK_ARRIVAL
        window = self.WINDOWS[event_type]
        ground_truth = self._compact_block_truth(truth)
        predicted = self._predictions_for_type(
            predictions,
            event_type,
            ground_truth,
            window,
            validation_start,
            validation_end,
        )
        return self._matching_row(
            dataset,
            event_type,
            self.LABELS[event_type],
            predicted,
            ground_truth,
            window,
            None,
            validation_start,
            validation_end,
        )

    def _large_transaction_row(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        large_transaction_min_bytes: int | None,
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        event_type = PassiveEventType.LARGE_TRANSACTION
        window = self.WINDOWS[event_type]
        ground_truth = self._large_transaction_truth(truth, large_transaction_min_bytes)
        predicted = self._predictions_for_type(
            predictions,
            event_type,
            ground_truth,
            window,
            validation_start,
            validation_end,
        )
        return self._matching_row(
            dataset,
            event_type,
            self.LABELS[event_type],
            predicted,
            ground_truth,
            window,
            None,
            validation_start,
            validation_end,
        )

    def _peer_discovery_row(
        self,
        dataset: str,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        event_type = PassiveEventType.PEER_DISCOVERY_RESPONSE
        window = self.WINDOWS[event_type]
        ground_truth = self._peer_discovery_truth(truth)
        predicted = self._predictions_for_type(
            predictions,
            event_type,
            ground_truth,
            window,
            validation_start,
            validation_end,
        )
        return self._matching_row(
            dataset,
            event_type,
            self.LABELS[event_type],
            predicted,
            ground_truth,
            window,
            None,
            validation_start,
            validation_end,
        )

    def _block_interval_predictions(
        self,
        predictions: list[PassiveEvent],
        block_truth: list[LogEvent],
        validation_start: float | None,
        validation_end: float | None,
    ) -> tuple[list[PassiveEvent], float]:
        size_predictions = self._block_size_predictions(predictions, block_truth, validation_start, validation_end)
        anchors = self._deduplicate_temporal_truth(block_truth, self.BLOCK_TEMPORAL_GROUP_SECONDS)
        window = self._block_interval_window(anchors, self.WINDOWS[PassiveEventType.BLOCK_ARRIVAL])
        if self.analysis_profile == "mainnet":
            return self._select_one_prediction_per_anchor(size_predictions, anchors, window), window
        return self._filter_predictions_by_intervals(size_predictions, anchors, window), window

    def _block_size_predictions(
        self,
        predictions: list[PassiveEvent],
        block_truth: list[LogEvent],
        validation_start: float | None,
        validation_end: float | None,
    ) -> list[PassiveEvent]:
        return self._predictions_for_type(
            predictions,
            PassiveEventType.BLOCK_ARRIVAL,
            block_truth,
            self.WINDOWS[PassiveEventType.BLOCK_ARRIVAL],
            validation_start,
            validation_end,
        )

    def _handshake_truth(self, truth: list[LogEvent]) -> list[LogEvent]:
        events = [event for event in truth if event.event_type in self.EVENT_MAP[PassiveEventType.BIP324_HANDSHAKE]]
        return self._deduplicate_handshake_truth(events)

    def _block_truth(self, truth: list[LogEvent]) -> list[LogEvent]:
        return [event for event in truth if event.event_type in self.EVENT_MAP[PassiveEventType.BLOCK_ARRIVAL]]

    def _profile_block_truth(self, truth: list[LogEvent]) -> list[LogEvent]:
        events = self._block_truth(truth)
        if self.analysis_profile != "mainnet":
            return events
        return self._mainnet_block_interval_truth(events)

    def _compact_block_truth(self, truth: list[LogEvent]) -> list[LogEvent]:
        return [
            event
            for event in truth
            if event.event_type == LogEventType.COMPACT_BLOCK_MESSAGE
        ]

    def _large_transaction_truth(
        self,
        truth: list[LogEvent],
        large_transaction_min_bytes: int | None,
    ) -> list[LogEvent]:
        if large_transaction_min_bytes is None:
            return []
        return [
            event
            for event in truth
            if event.event_type == LogEventType.TX_OR_RELAY_MESSAGE
            and event.message_type == "tx"
            and event.message_size is not None
            and event.message_size >= large_transaction_min_bytes
        ]

    def _peer_discovery_truth(self, truth: list[LogEvent]) -> list[LogEvent]:
        return [
            event
            for event in truth
            if event.event_type == LogEventType.PEER_DISCOVERY_MESSAGE
            and event.message_type in {"addr", "addrv2"}
            and event.message_size is not None
            and event.message_size > 0
        ]

    def _predictions_for_type(
        self,
        predictions: list[PassiveEvent],
        event_type: PassiveEventType,
        ground_truth: list[LogEvent],
        window: float,
        validation_start: float | None,
        validation_end: float | None,
    ) -> list[PassiveEvent]:
        return [
            event
            for event in predictions
            if event.event_type == event_type
            and self._prediction_has_validation_scope(event, ground_truth, window, validation_start, validation_end)
        ]

    def _count_row(
        self,
        dataset: str,
        event_type: PassiveEventType,
        label: str,
        predicted: list[PassiveEvent],
        ground_truth: list[LogEvent],
        window: float,
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        tp = min(len(predicted), len(ground_truth))
        fp = max(0, len(predicted) - len(ground_truth))
        fn = max(0, len(ground_truth) - len(predicted))
        return self._row_from_counts(
            dataset,
            event_type,
            label,
            len(predicted),
            len(ground_truth),
            tp,
            fp,
            fn,
            window,
            validation_start,
            validation_end,
        )

    def _matching_row(
        self,
        dataset: str,
        event_type: PassiveEventType,
        label: str,
        predicted: list[PassiveEvent],
        ground_truth: list[LogEvent],
        window: float,
        bitcoin_flow_ids: set[str] | None,
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        tp, fp, fn = self._match(predicted, ground_truth, window, bitcoin_flow_ids)
        return self._row_from_counts(
            dataset,
            event_type,
            label,
            len(predicted),
            len(ground_truth),
            tp,
            fp,
            fn,
            window,
            validation_start,
            validation_end,
        )

    @staticmethod
    def _row_from_counts(
        dataset: str,
        event_type: PassiveEventType,
        label: str,
        predicted_count: int,
        ground_truth_count: int,
        true_positive: int,
        false_positive: int,
        false_negative: int,
        window: float,
        validation_start: float | None,
        validation_end: float | None,
    ) -> EvaluationRow:
        precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
        recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return EvaluationRow(
            dataset=dataset,
            event_type=event_type,
            label=label,
            predicted_count=predicted_count,
            ground_truth_count=ground_truth_count,
            true_positive=true_positive,
            false_positive=false_positive,
            false_negative=false_negative,
            detector_error_count=false_positive + false_negative,
            precision=precision,
            recall=recall,
            f1=f1,
            miss_rate=false_negative / ground_truth_count if ground_truth_count else 0.0,
            false_alarm_rate=false_positive / predicted_count if predicted_count else 0.0,
            matching_window_seconds=window,
            validation_start_time=validation_start,
            validation_end_time=validation_end,
        )

    @staticmethod
    def _inside_validation_window(
        events: list[PassiveEvent] | list[LogEvent],
        start: float | None,
        end: float | None,
    ):
        if start is None or end is None:
            return events
        return [event for event in events if start <= event.timestamp <= end]

    @staticmethod
    def _deduplicate_handshake_truth(events: list[LogEvent]) -> list[LogEvent]:
        by_connection: dict[tuple[str, int | str | None], LogEvent] = {}
        for event in sorted(events, key=lambda item: item.timestamp):
            key = (event.node, event.peer_id if event.peer_id is not None else event.peer_addr)
            by_connection.setdefault(key, event)
        return sorted(by_connection.values(), key=lambda item: item.timestamp)

    @staticmethod
    def _deduplicate_temporal_truth(events: list[LogEvent], group_seconds: float) -> list[LogEvent]:
        grouped = PredictionValidator._temporal_groups(events, group_seconds)
        return [group[0] for group in grouped]

    @staticmethod
    def _filter_predictions_by_intervals(
        predictions: list[PassiveEvent],
        anchors: list[LogEvent],
        window: float,
    ) -> list[PassiveEvent]:
        if not anchors:
            return predictions
        windows: list[tuple[float, float]] = []
        for event in sorted(anchors, key=lambda item: item.timestamp):
            start = event.timestamp - window
            end = event.timestamp + window
            if windows and start <= windows[-1][1]:
                windows[-1] = (windows[-1][0], max(windows[-1][1], end))
            else:
                windows.append((start, end))
        return [
            prediction
            for prediction in predictions
            if any(start <= prediction.timestamp <= end for start, end in windows)
        ]

    @staticmethod
    def _select_one_prediction_per_anchor(
        predictions: list[PassiveEvent],
        anchors: list[LogEvent],
        window: float,
    ) -> list[PassiveEvent]:
        selected: list[PassiveEvent] = []
        remaining = sorted(predictions, key=lambda event: event.timestamp)
        for anchor in sorted(anchors, key=lambda event: event.timestamp):
            candidates = [
                prediction
                for prediction in remaining
                if abs(prediction.timestamp - anchor.timestamp) <= window
            ]
            if not candidates:
                continue
            best = max(candidates, key=lambda event: (event.observed_bytes, -abs(event.timestamp - anchor.timestamp)))
            selected.append(best)
            remaining = [prediction for prediction in remaining if prediction is not best]
        return selected

    @classmethod
    def _interval_window(cls, anchors: list[LogEvent], fallback: float) -> float:
        if len(anchors) < 2:
            return fallback
        deltas = [
            current.timestamp - previous.timestamp
            for previous, current in zip(anchors, anchors[1:])
            if current.timestamp > previous.timestamp
        ]
        if not deltas:
            return fallback
        median_delta = cls._median(deltas)
        return max(1.0, min(fallback, median_delta * cls.BLOCK_INTERVAL_WINDOW_FRACTION))

    def _block_interval_window(self, anchors: list[LogEvent], fallback: float) -> float:
        if self.analysis_profile == "mainnet":
            return self.MAINNET_BLOCK_INTERVAL_TOLERANCE_SECONDS
        return self._interval_window(anchors, fallback)

    def _mainnet_block_interval_truth(self, events: list[LogEvent]) -> list[LogEvent]:
        selected: list[LogEvent] = []
        minimum_gap = self.MAINNET_BLOCK_INTERVAL_SECONDS - self.MAINNET_BLOCK_INTERVAL_TOLERANCE_SECONDS
        for event in sorted(events, key=lambda item: item.timestamp):
            if not selected or event.timestamp - selected[-1].timestamp >= minimum_gap:
                selected.append(event)
        return selected

    @staticmethod
    def _median(values: list[float]) -> float:
        ordered = sorted(values)
        middle = len(ordered) // 2
        if len(ordered) % 2:
            return ordered[middle]
        return (ordered[middle - 1] + ordered[middle]) / 2

    @staticmethod
    def _temporal_groups(events, group_seconds: float):
        groups = []
        for event in sorted(events, key=lambda item: (item.dataset, item.timestamp)):
            if (
                not groups
                or groups[-1][-1].dataset != event.dataset
                or event.timestamp - groups[-1][-1].timestamp > group_seconds
            ):
                groups.append([event])
            else:
                groups[-1].append(event)
        return groups

    @staticmethod
    def _prediction_has_validation_scope(
        prediction: PassiveEvent,
        truth: list[LogEvent],
        window: float,
        validation_start: float | None,
        validation_end: float | None,
    ) -> bool:
        if validation_start is None or validation_end is None:
            return True
        if validation_start <= prediction.timestamp <= validation_end:
            return True
        return any(abs(event.timestamp - prediction.timestamp) <= window for event in truth)

    @staticmethod
    def _match(
        predicted: list[PassiveEvent],
        truth: list[LogEvent],
        window: float,
        bitcoin_flow_ids: set[str] | None,
    ) -> tuple[int, int, int]:
        truth_by_dataset: dict[str, list[tuple[int, LogEvent]]] = defaultdict(list)
        for idx, event in enumerate(truth):
            truth_by_dataset[event.dataset].append((idx, event))

        matched_truth: set[int] = set()
        true_positive = 0
        false_positive = 0
        for prediction in sorted(predicted, key=lambda event: event.timestamp):
            if bitcoin_flow_ids is not None and prediction.flow_id not in bitcoin_flow_ids:
                false_positive += 1
                continue
            candidates = [
                (idx, abs(event.timestamp - prediction.timestamp))
                for idx, event in truth_by_dataset.get(prediction.dataset, [])
                if idx not in matched_truth and abs(event.timestamp - prediction.timestamp) <= window
            ]
            if candidates:
                best_idx, _delta = min(candidates, key=lambda item: item[1])
                matched_truth.add(best_idx)
                true_positive += 1
            else:
                false_positive += 1

        false_negative = max(0, len(truth) - len(matched_truth))
        return true_positive, false_positive, false_negative

    @staticmethod
    def _false_positive_matches(
        predicted: list[PassiveEvent],
        truth: list[LogEvent],
        window: float,
        bitcoin_flow_ids: set[str] | None,
    ) -> list[tuple[PassiveEvent, str, float]]:
        truth_by_dataset: dict[str, list[tuple[int, LogEvent]]] = defaultdict(list)
        for idx, event in enumerate(truth):
            truth_by_dataset[event.dataset].append((idx, event))

        matched_truth: set[int] = set()
        false_positives: list[tuple[PassiveEvent, str, float]] = []
        for prediction in sorted(predicted, key=lambda event: event.timestamp):
            if bitcoin_flow_ids is not None and prediction.flow_id not in bitcoin_flow_ids:
                false_positives.append((prediction, "non_bitcoin_or_noise_flow", window))
                continue
            candidates = [
                (idx, abs(event.timestamp - prediction.timestamp))
                for idx, event in truth_by_dataset.get(prediction.dataset, [])
                if idx not in matched_truth and abs(event.timestamp - prediction.timestamp) <= window
            ]
            if candidates:
                best_idx, _delta = min(candidates, key=lambda item: item[1])
                matched_truth.add(best_idx)
            else:
                false_positives.append((prediction, "no_ground_truth_match_in_window", window))
        return false_positives

    def _generic_false_positive_matches(
        self,
        predictions: list[PassiveEvent],
        truth: list[LogEvent],
        event_type: PassiveEventType,
        window: float,
        validation_start: float | None,
        validation_end: float | None,
    ) -> list[tuple[PassiveEvent, str, float]]:
        predicted = self._predictions_for_type(
            predictions,
            event_type,
            truth,
            window,
            validation_start,
            validation_end,
        )
        return self._false_positive_matches(predicted, truth, window, None)
