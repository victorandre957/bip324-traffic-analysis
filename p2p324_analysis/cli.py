import argparse
from pathlib import Path

from .pipeline import (
    AnalysisPipeline,
    DatasetConfig,
    discover_default_datasets,
    discover_directory_datasets,
)


DEFAULT_WARNET_OUTPUT = "results"
DEFAULT_MAINNET_OUTPUT = "mainnet_results"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Bitcoin P2P v2/BIP324 traffic from local PCAPs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--root", default=".", help="Repository root used for default dataset discovery.")
    parser.add_argument("--output", default=None, help="Directory where CSV/JSON reports will be written.")

    custom = parser.add_argument_group("custom single-capture mode")
    custom.add_argument("--pcap", action="append", help="Custom PCAP path. Can be passed more than once.")
    custom.add_argument("--log", action="append", default=[], help="Debug log path for custom PCAP mode.")
    custom.add_argument("--ip-map", default=None, help="Warnet ip-map.txt path for custom PCAP mode.")
    custom.add_argument("--metadata", default=None, help="metadata.json path for custom PCAP mode.")
    custom.add_argument("--name", default="custom", help="Dataset name for custom PCAP mode.")

    directory = parser.add_argument_group("directory discovery mode")
    directory.add_argument("--data-dir", default=None, help="Directory to scan for PCAP/log files.")
    directory.add_argument("--pcap-glob", default="*.pcap", help="Glob used with --data-dir or --mainnet.")
    directory.add_argument("--log-glob", default="debug*.log", help="Optional log glob used with --data-dir or --mainnet.")
    directory.add_argument("--dataset-prefix", default=None, help="Dataset name prefix used with --data-dir.")

    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="Analyze only mainnet captures from mainnet_data, without requiring ip-map.txt.",
    )
    parser.add_argument(
        "--mainnet-data-dir",
        default=None,
        help="Override the mainnet data directory. Defaults to <root>/mainnet_data.",
    )
    args = parser.parse_args()

    if args.pcap:
        datasets = [
            DatasetConfig(
                name=args.name if len(args.pcap) == 1 else f"{args.name}-{idx}",
                pcap_path=Path(pcap),
                log_paths=[Path(path) for path in args.log],
                ip_map_path=Path(args.ip_map) if args.ip_map else None,
                metadata_path=Path(args.metadata) if args.metadata else None,
                analysis_profile="custom",
            )
            for idx, pcap in enumerate(args.pcap, start=1)
        ]
    elif args.mainnet:
        root = Path(args.root)
        mainnet_dir = (
            Path(args.mainnet_data_dir)
            if args.mainnet_data_dir
            else _default_mainnet_dir(root)
        )
        datasets = discover_directory_datasets(
            mainnet_dir,
            pcap_glob=args.pcap_glob,
            log_glob=args.log_glob,
            dataset_prefix=args.dataset_prefix or "mainnet",
            analysis_profile="mainnet",
        )
    elif args.data_dir:
        datasets = discover_directory_datasets(
            args.data_dir,
            pcap_glob=args.pcap_glob,
            log_glob=args.log_glob,
            dataset_prefix=args.dataset_prefix,
        )
    else:
        datasets = discover_default_datasets(args.root)

    if not datasets:
        raise SystemExit(
            "No datasets found. Pass --pcap, use --data-dir, add Warnet runs under data_to_analysis, "
            "or use --mainnet for mainnet_data."
        )

    output_dir = args.output or (DEFAULT_MAINNET_OUTPUT if args.mainnet else DEFAULT_WARNET_OUTPUT)
    AnalysisPipeline(output_dir).run(datasets)


def _default_mainnet_dir(root: Path) -> Path:
    return root / "mainnet_data"


if __name__ == "__main__":
    main()
