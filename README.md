# BIP324 Traffic Analysis

Passive analysis for Bitcoin P2P v2/BIP324 packet captures.

The analyzer reads PCAP metadata and writes CSV/JSON reports. Bitcoin Core logs
and `ip-map.txt` are used only to validate the passive detections and explain
false positives.

The current reports cover BIP324 handshakes, block arrivals, compact-block-sized
bursts, large transaction bursts, and address-response-sized bursts.

For code structure and execution order, see `ARCHITECTURE.md`.

## Detection Criteria

- BIP324 handshake: TCP flow that passes explicit checks for encrypted-looking
  payloads, initial BIP324-sized flights, no cleartext protocol hint, and
  bidirectional exchange. Initial BIP324 flights are expected to be between
  `64` and `4159` bytes, and the validation window is `5s`.
- Block arrival: burst size close to the average logged block/compact-block
  size, with an additional size-plus-interval comparison. Warnet uses the
  dataset's mined-block cadence; mainnet uses a `600s` block interval with a
  `120s` tolerance and keeps at most one candidate per expected interval.
- Compact block arrival: burst size close to the average logged `cmpctblock`
  message size, validated with a `4s` window.
- Large transaction: Warnet uses the 90th percentile of logged `tx` sizes;
  mainnet uses the 99th percentile to match mainnet-scale transaction
  outliers. Validation uses a `3s` window.
- Address response: Warnet uses the average logged `addrv2` size and restricts
  candidates to early-session bursts; mainnet uses the 95th percentile of
  logged `addrv2` sizes and does not require the event to happen near session
  start. Validation uses a `3s` window.

The derived byte thresholds for each run are written to
`notebook_dataset_scope.csv`.

For the included sample data, the current derived thresholds are:

| Profile | Block bytes | Compact block bytes | Large tx bytes | Address bytes | Block timing |
| --- | ---: | ---: | ---: | ---: | --- |
| Warnet | 271 | 271 | 518 | 21 | observed cadence, 6.36s in this sample |
| Mainnet | 1,528,423 | 24,057 | 2,779 | 232 | 600s interval, 120s tolerance |

## Requirements

- Python 3.11 or newer
- Warnet data in `data_to_analysis/`

The expected `data_to_analysis/` files are produced by `bip324-traffic-lab`.

## Setup

From this directory:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Input

Default Warnet input:

```text
data_to_analysis/
  isp-capture.pcap
  tank-0001-debug.log
  tank-0002-debug.log
  tank-0003-debug.log
  ip-map.txt
  metadata.json
```

Runs can also be stored as subdirectories:

```text
data_to_analysis/
  run-YYYYMMDDHHMMSS/
    isp-capture.pcap
    tank-0001-debug.log
    tank-0002-debug.log
    tank-0003-debug.log
    ip-map.txt
    metadata.json
```

## Run

Warnet analysis:

```bash
python run_analysis.py
```

Warnet results are written to `results/`.

Mainnet analysis:

```bash
python run_analysis.py --mainnet
```

Mainnet results are written to `mainnet_results/`.

## Mainnet Capture

To create a mainnet dataset, run a local Bitcoin Core node with P2P v2 enabled
and capture its P2P traffic with `tcpdump`.

Example `bitcoin.conf` entries:

```text
v2transport=1
debug=net
debug=mempool
debug=cmpctblock
logtimemicros=1
```

Start Bitcoin Core, wait until it has active peers, then capture host traffic.
Capturing all host traffic gives the mainnet analysis real background noise;
capturing only `tcp port 8333` is useful for a Bitcoin-only control run.

```bash
sudo tcpdump -i any -w mainnet_data/captura_p2p_v2.pcap
```

If you want a Bitcoin-only capture instead, use `tcp port 8333` as the tcpdump
filter.

After the capture, copy the matching Bitcoin Core log to:

```text
mainnet_data/debug.log
```

Then run:

```bash
python run_analysis.py --mainnet
```

Mainnet captures do not have labeled noise endpoints, so
`analyze_mainnet.ipynb` omits the noise-confusion view.

## Outputs

- `summary.json`
- `flow_features.csv`
- `passive_events.csv`
- `log_events.csv`
- `evaluation.csv`
- `false_positive_events.csv`
- `notebook_dataset_scope.csv`
- `notebook_validation.csv`
- `notebook_block_arrival_comparison.csv`
- `notebook_false_positive_noise.csv`
- `notebook_passive_summary.csv`
- `notebook_passive_timeseries.csv`
- `notebook_bip324_candidates.csv`

## Notebooks

Run the analysis first, then open:

- `analyze_warnet.ipynb`
- `analyze_mainnet.ipynb`

`analyze_warnet.ipynb` reads `results/`. `analyze_mainnet.ipynb` reads
`mainnet_results/`. They display tables only and do not run the analysis
pipeline.

The published notebooks may keep the rendered summary tables so readers can see
the results without running the pipeline. Do not render raw flow tables,
`false_positive_events.csv`, `passive_events.csv`, or endpoint columns from
`notebook_bip324_candidates.csv`, because those files can include local IPs,
peer IPs, timestamps, and capture-specific details.

## Example result

For the included sample Warnet data, `notebook_validation.csv` reports the
number of predicted events, ground-truth events, true positives, false
positives, false negatives, precision, recall, and F1 for each detection case.

## Reproducibility

Keep the input capture, logs, `ip-map.txt`, `metadata.json`, the analysis
command, and the matching output directory.

When the input comes from `bip324-traffic-lab`, `metadata.json` records the seed
used to reproduce generated payloads, parameters, and pseudo-random choices.
Exact PCAP bytes can still vary because packet timing depends on Kubernetes
scheduling.
