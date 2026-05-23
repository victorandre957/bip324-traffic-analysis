# BIP324 Traffic Analysis Architecture

The analyzer is a local, file-based pipeline. It reads captures and logs, writes
CSV/JSON reports, and leaves notebooks as display-only documents.

## Execution Order

1. `cli.py` resolves the input mode: Warnet data, mainnet data, or custom PCAPs.
2. `pipeline.py` runs the analysis for each dataset.
3. `read_pcap.py` extracts packet-level metadata from each PCAP.
4. `build_flows.py` groups packets into bidirectional flows.
5. `detect_passive.py` emits passive metadata detections.
6. `read_bitcoin_logs.py` and `read_ip_map.py` load ground truth when available.
7. `validate_predictions.py` compares passive detections with ground truth.
8. `write_reports.py` writes the CSV and JSON files used by the notebooks.

## BIP324 Handshake Detection

The handshake detector uses explicit requirements instead of a weighted score.
Each candidate flow records whether it satisfies checks such as TCP transport,
enough payload packets, plausible initial payload sizes, balanced first payload
flights, high entropy, no cleartext protocol hint, and active payload exchange.

The output file `notebook_bip324_candidates.csv` exposes these checks directly
so the decision can be inspected without reading the implementation.

## Event Detection

The validation table covers the passive cases that are visible in the current
inputs:

- BIP324 handshake candidates;
- block arrivals by size and by size plus interval;
- compact-block-sized bursts;
- large transaction bursts, with the size threshold derived from the top of the
  transaction-size distribution in the current run;
- address-response-sized bursts after `getaddr` activity.

Warnet logs provide validation labels. Mainnet logs are used when available, but
mainnet validation is necessarily less controlled than the lab dataset.

## Added Event Criteria

The added detectors use thresholds derived from the current dataset logs when
ground truth is available:

- compact block: average logged `cmpctblock` message size, matched against
  compact-block-sized passive bursts and validated within 4 seconds;
- large transaction: Warnet uses the 90th percentile of logged `tx` sizes, while
  mainnet uses the 99th percentile because ordinary mainnet transactions are
  much more varied;
- address response: Warnet uses the average logged `addrv2` size near session
  startup, while mainnet uses the 95th percentile of logged `addrv2` sizes
  without an early-session restriction.

Block-arrival timing also depends on the profile:

- Warnet derives the timing window from the run's observed block cadence, after
  grouping block-log events within 3 seconds.
- Mainnet uses a 600-second block interval with a 120-second tolerance and keeps
  at most one passive candidate per expected interval.

These cases are intentionally approximate. The goal is to test whether passive
metadata carries a visible signal, not to claim perfect classification.
