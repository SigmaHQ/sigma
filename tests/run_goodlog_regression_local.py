"""Local goodlog test runner - downloads baselines and checker, then validates findings."""

import argparse
import platform
import stat
import subprocess
import sys
import tarfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_BASELINE_BASE_URL = "https://github.com/NextronSystems/evtx-baseline/releases/download"

BASELINES: list[tuple[str, str]] = [
    ("win7-x86.tgz", "win7-x86"),
    ("win10-client.tgz", "Logs_Client"),
    ("win11-client.tgz", "Logs_Win11"),
    ("win11-client-2023.tgz", "Logs_Win11_2023"),
    ("win2022-evtx.tgz", "win2022-evtx"),
    ("win2022-ad.tgz", "Win2022-AD"),
    ("win2022-0-20348-azure.tgz", "win2022-0-20348-azure"),
]


def _download(url: str, dest: Path) -> None:
    print(f"  Downloading {url}")
    urllib.request.urlretrieve(url, dest)


def ensure_checker(checker_path: Path, version: str) -> None:
    if checker_path.exists():
        print(f"  {checker_path}: already present, skipping download")
        return
    system = platform.system()
    if system == "Linux":
        filename = "evtx-sigma-checker"
    elif system == "Darwin":
        filename = "evtx-sigma-checker-darwin"
    else:
        raise RuntimeError(f"Unsupported OS: {system}")
    _download(f"{_BASELINE_BASE_URL}/{version}/{filename}", checker_path)
    checker_path.chmod(checker_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def ensure_baseline(tgz_name: str, dir_name: str, version: str, work_dir: Path) -> Path:
    target = work_dir / dir_name
    if target.exists():
        print(f"  {dir_name}: already present, skipping download")
        return target
    tgz_path = work_dir / tgz_name
    _download(f"{_BASELINE_BASE_URL}/{version}/{tgz_name}", tgz_path)
    print(f"  Extracting {tgz_name}...")
    with tarfile.open(tgz_path) as tf:
        tf.extractall(work_dir)
    tgz_path.unlink()
    return target


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-version", required=True, help="evtx-baseline release version (e.g. v0.8.4)")
    parser.add_argument("--evtx-checker", default="evtx-sigma-checker", help="Path to evtx-sigma-checker binary")
    parser.add_argument("--log-source", default="tests/thor.yml")
    parser.add_argument(
        "--rule-paths",
        nargs="+",
        default=["rules/windows/", "rules-emerging-threats/", "rules-threat-hunting/"],
    )
    parser.add_argument("--deprecated-paths", nargs="+", default=["deprecated/"])
    parser.add_argument("--known-fps", default=".github/workflows/known-FPs.csv")
    parser.add_argument("--findings", default="findings.json")
    parser.add_argument("--work-dir", default=".", help="Directory for baseline downloads")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    checker_path = Path(args.evtx_checker)

    print(f"Ensuring evtx-sigma-checker ({args.baseline_version})...")
    ensure_checker(checker_path, args.baseline_version)

    print(f"\nDownloading baselines ({args.baseline_version})...")
    evtx_dirs: list[Path] = []
    dl_errors: list[str] = []
    with ThreadPoolExecutor() as pool:
        futures = {
            pool.submit(ensure_baseline, tgz, d, args.baseline_version, work_dir): d
            for tgz, d in BASELINES
        }
        for future in as_completed(futures):
            try:
                evtx_dirs.append(future.result())
            except Exception as e:
                dl_errors.append(str(e))
    if dl_errors:
        for e in dl_errors:
            print(f"ERROR: {e}")
        return 1

    print("\nRunning evtx-sigma-checker across all baselines...")
    cmd = [str(checker_path), "--log-source", args.log_source]
    for d in evtx_dirs:
        cmd += ["--evtx-path", str(d)]
    for p in args.rule_paths:
        cmd += ["--rule-path", p]
    with open(args.findings, "w") as f:
        result = subprocess.run(cmd, stdout=f)
    if result.returncode != 0:
        print(f"ERROR: evtx-sigma-checker exited with code {result.returncode}")
        return result.returncode
    print("Done.\n")

    print("Validating findings...")
    validation = subprocess.run([
        sys.executable,
        str(Path(__file__).parent / "run_goodlog_regression.py"),
        "--findings", args.findings,
        "--known-fps", args.known_fps,
        "--rule-paths", *args.rule_paths,
        "--deprecated-paths", *args.deprecated_paths,
    ])
    return validation.returncode


if __name__ == "__main__":
    sys.exit(main())
