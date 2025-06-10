#!/usr/bin/python3
import argparse
import csv
import os
import sys
import logging
import subprocess
import time
import gc
from contextlib import contextmanager
from multiprocessing import cpu_count
from collections import defaultdict

# import CFG_recover from "/work/src/CFG_recover.py"
sys.path.append("/work/src")
import bz_common as bzc  # noqa E402
from CFG_transform import CFGTransformer
from bb_match import (
    BBMatcher,
    LabradorMatcher,
    RegexMatcher,
    augment_must_bbs,
    aggressive_augment,
)

ghidra_dir = "/work/static-analysis-result"
out_dir = os.environ.get("SHEPHERD_PRECISION_DIR", "/dev/shm/rgf_precision")
cache_dir = os.path.join(out_dir, "pin_output")


@contextmanager
def disable_gc():
    """Temporarily disable the garbage collector."""
    gc_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if gc_enabled:
            gc.enable()


def is_running_in_docker():
    return os.path.exists("/.dockerenv")


def unpack_seeds(target_dir):
    target_name = os.path.basename(target_dir)
    # the seed file is target_dir/seed.zip
    seed_zip = os.path.join(target_dir, "seed.zip")
    output_dir = os.path.join(out_dir, "seeds", target_name)
    if os.path.exists(output_dir):
        logging.info(f"Seeds already unpacked in {output_dir}")
        return output_dir
    os.makedirs(output_dir, exist_ok=True)
    logging.info(f"Unpacking {seed_zip} to {output_dir}")
    os.system(f"unzip -q {seed_zip} -d {output_dir}")
    return output_dir


def find_all_files_deep(directory):
    all_files = []
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"{directory} is not a directory")

    for root, _, files in os.walk(directory):
        for file in files:
            all_files.append(os.path.join(root, file))
    all_files.sort()
    return all_files


def get_edges(edge_bytes):
    edges = []
    for i in range(0, len(edge_bytes), 16):
        src = int.from_bytes(edge_bytes[i : i + 8], "little")
        dst = int.from_bytes(edge_bytes[i + 8 : i + 16], "little")
        edges.append((src, dst))
    return edges


# Remove stuff such as "jpc_dec_tilefini called\njpc_dec_tilefini called"
def remove_consecutive_duplicates(response):
    response_lines = response.splitlines()
    new_response_lines = []
    last_line = b""
    for line in response_lines:
        if line != last_line:
            new_response_lines.append(line)
            last_line = line
    return b"\n".join(new_response_lines)


def run_PIN_put(target_dir, input_file):
    os.path.basename(target_dir)
    put_bin = os.path.join(target_dir, "put_bin")
    command_file = os.path.join(target_dir, "cmd.sh")
    with open(command_file, "r") as f:
        cmd = f.read().strip()
    cmd = cmd.replace("$PUT_BIN", put_bin)
    pin_cmd = ["pin", "-t", "pintools/pintool_for_shepherd.so", "--"]
    cmd = cmd.replace("@@", input_file)
    cmd = cmd.split(" ")
    pin_cmd.extend(cmd)

    process = subprocess.Popen(
        pin_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )

    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()  # Send SIGTERM and let pintool_finish to run
        print(f"Timeout for {input_file}")
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()

    pid = process.pid
    out_file = f"/tmp/edges/edge_{pid}"
    with open(out_file, "rb") as f:
        edge_bytes = f.read()
    edges = get_edges(edge_bytes)
    response = stdout + stderr

    response = remove_consecutive_duplicates(response)

    return response, edges


def build_minimized_cfg(target):
    cfg, _, _ = bzc.load_static_analysis_result(os.path.join(ghidra_dir, target))
    transformer = CFGTransformer(cfg)
    transformer.run_all_passes(cfg)
    cfg.build_dominators()
    cfg.build_func_distance_map()
    return cfg


def get_estimations(
    response, shepherd_matcher, lab_low_matcher, lab_high_matcher, regex_matcher
):
    # Shepherd
    with disable_gc():
        shepherd_start = time.perf_counter()
        shepherd_bbs = (shepherd_matcher.search_bbs(response), "shepherd")
        shepherd_end = time.perf_counter()
    gc.collect()
    # Shepherd-Simple (not timed)
    shepherd_simple_bbs = (
        shepherd_matcher.search_bbs_without_beam(response),
        "shepherd_simple",
    )
    # Labrador (low)
    with disable_gc():
        labrador_start = time.perf_counter()
        labrador_low_bbs = (lab_low_matcher.get_labrador_bbs(response), "labrador_low")
        labrador_end = time.perf_counter()
    # Labrador (high) call (not timed)
    gc.collect()
    with disable_gc():
        labrador_high_bbs = (
            lab_high_matcher.get_labrador_bbs(response),
            "labrador_high",
        )

    gc.collect()
    with disable_gc():
        regex_start = time.perf_counter()
        # This next line is intentionally not added to the results list below
        regex_bbs = (regex_matcher.search_bbs(response), "regex")
        regex_end = time.perf_counter()

    gc.collect()

    shepherd_time = shepherd_end - shepherd_start
    labrador_time = labrador_end - labrador_start
    regex_time = regex_end - regex_start

    return (
        [shepherd_bbs, shepherd_simple_bbs, labrador_low_bbs, labrador_high_bbs],
        shepherd_time,
        labrador_time,
        regex_time,
    )


def get_precision_stats(real_bbs, estim_bbs):
    tp = estim_bbs.intersection(real_bbs)
    fp = estim_bbs.difference(real_bbs)
    fn = real_bbs.difference(estim_bbs)

    try:
        recall = len(tp) / (len(tp) + len(fn))
        precision = len(tp) / len(estim_bbs)
        f1 = 2 * precision * recall / (precision + recall)
    except ZeroDivisionError:
        recall = 0
        precision = 0
        f1 = 0

    return [
        (len(tp), "True-P"),
        (len(fp), "Fals-P"),
        (len(fn), "Fals-N"),
        (precision, "Precision"),
        (recall, "Recall"),
        (f1, "F1"),
    ]


# Generic method to run a function with a timeout
def run_func_timeout(generic_func, timeout):
    def func_wrapper(*args, **kwargs):
        try:
            return generic_func(*args, **kwargs)
        except Exception as e:
            print(f"Exception: {e}")
            return None

    return func_wrapper


def process_target(target_root, target):
    target_dir = os.path.join(target_root, target)
    unpacked_seeds_dir = unpack_seeds(target_dir)
    all_seeds = find_all_files_deep(unpacked_seeds_dir)
    min_cfg = build_minimized_cfg(target)

    orig_cfg, _, _ = bzc.load_static_analysis_result(os.path.join(ghidra_dir, target))
    # Create necessary directories for caching
    responses_dir = os.path.join(cache_dir, target, "responses")
    edges_dir = os.path.join(cache_dir, target, "edges")
    bbs_dir = os.path.join(cache_dir, target, "bbs")
    prec_dir = os.path.join(out_dir, "precision")
    time_dir = os.path.join(out_dir, "time")

    for dirpath in [responses_dir, edges_dir, bbs_dir, prec_dir, time_dir]:
        os.makedirs(dirpath, exist_ok=True)

    seed_map_file = os.path.join(cache_dir, target, "seed_map.txt")
    with open(seed_map_file, "w") as f:
        for seed_id, seed in enumerate(all_seeds):
            seed_fixed = seed.encode("utf-8", "surrogateescape").decode("utf-8")
            f.write(f"{seed_id}: {seed_fixed}\n")

    # File for precision statistics per seed
    result_file = os.path.join(prec_dir, f"{target}.csv")
    with open(result_file, mode="w", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [
                "Seed ID",
                "Algo",
                "Augment",
                "True-P",
                "False-P",
                "False-N",
                "Precision",
                "Recall",
                "F1",
            ]
        )

    # New file for timing information per seed
    timing_file = os.path.join(time_dir, f"{target}.csv")
    with open(timing_file, mode="w", newline="") as tf:
        time_writer = csv.writer(tf)
        time_writer.writerow(
            [
                "Seed ID",
                "Shepherd Time",
                "Labrador Time",
                "Regex Time",
            ]
        )

    print(f"Processing {target} with {len(all_seeds)} seeds")
    shepherd_total_time = 0
    labrador_total_time = 0
    regex_total_time = 0

    shepherd_bb_matcher = BBMatcher(min_cfg)
    # No-cache labrador matcher
    lab_low_matcher = LabradorMatcher(min_cfg, 0.35)
    lab_high_matcher = LabradorMatcher(min_cfg, 0.70)
    regex_matcher = RegexMatcher(min_cfg)

    string_refer_bbs = orig_cfg.get_string_refer_bbs()
    for seed_id, seed in enumerate(all_seeds):
        if not os.path.exists(os.path.join(responses_dir, f"{seed_id}.txt")):
            print(f"PINning on seed {seed_id}: {seed}")
            response, edges = run_PIN_put(target_dir, seed)
            real_bbs = orig_cfg.convert_edges_to_BBs(edges) & string_refer_bbs

            with open(os.path.join(responses_dir, f"{seed_id}.txt"), "wb") as f:
                f.write(response)
            with open(os.path.join(edges_dir, f"{seed_id}.txt"), "w") as f:
                for edge in edges:
                    f.write(f"{edge[0]:x} -> {edge[1]:x}\n")
            with open(os.path.join(bbs_dir, f"{seed_id}.txt"), "w") as f:
                for bb in real_bbs:
                    f.write(f"{bb.start_addr:x}\n")
        else:
            response = open(os.path.join(responses_dir, f"{seed_id}.txt"), "rb").read()
            real_bbs = open(os.path.join(bbs_dir, f"{seed_id}.txt"), "r").readlines()
            real_bbs = [int(bb.strip(), 16) for bb in real_bbs]
            real_bbs = [orig_cfg.get_bb_from_addr(bb) for bb in real_bbs]
            real_bbs = {bb for bb in real_bbs if bb is not None}
            real_bbs = real_bbs & string_refer_bbs

        (
            estim_bbs_list,
            shepherd_time,
            labrador_time,
            regex_time,
        ) = get_estimations(
            response,
            shepherd_bb_matcher,
            lab_low_matcher,
            lab_high_matcher,
            regex_matcher,
        )
        shepherd_total_time += shepherd_time
        labrador_total_time += labrador_time
        regex_total_time += regex_time
        # seed path only has path after "seeds" dir
        seed_path_str = seed.split("seeds/")[1]
        print(
            f"Seed {seed_id}: {seed_path_str} S({shepherd_time:.2f}) L({labrador_time:.2f}) R({regex_time:.2f})"
        )

        # Write timing info for this seed to the CSV
        with open(timing_file, mode="a", newline="") as tf:
            time_writer = csv.writer(tf)
            time_writer.writerow(
                [
                    seed_id,
                    shepherd_time,
                    labrador_time,
                    regex_time,
                ]
            )

        # Collect stats for each estimation
        stats_per_method = defaultdict(list)
        for estim_bbs, name in estim_bbs_list:
            estim_stats = get_precision_stats(real_bbs, estim_bbs)
            must_bbs = augment_must_bbs(estim_bbs)
            must_stats = get_precision_stats(real_bbs, must_bbs)
            aggressive_bbs = aggressive_augment(estim_bbs)
            aggressive_stats = get_precision_stats(real_bbs, aggressive_bbs)

            stats_per_method[name].append(("RAW", estim_stats))
            # Uncomment if needed:
            # stats_per_method[name].append(("MUST", must_stats))
            # stats_per_method[name].append(("MANY", aggressive_stats))

        # Write precision stats to the result CSV file
        with open(result_file, mode="a", newline="") as f:
            csv_writer = csv.writer(f)
            for estimator, stats_list in stats_per_method.items():
                for method, stats in stats_list:
                    true_positive = stats[0][0]
                    false_positive = stats[1][0]
                    false_negative = stats[2][0]
                    precision = round(stats[3][0], 4)
                    recall = round(stats[4][0], 4)
                    f1 = round(stats[5][0], 4)

                    csv_writer.writerow(
                        [
                            seed_id,
                            estimator,
                            method,
                            true_positive,
                            false_positive,
                            false_negative,
                            precision,
                            recall,
                            f1,
                        ]
                    )
    print(f"  Total Shepherd: {shepherd_total_time}")
    print(f"  Total Labrador: {labrador_total_time}")
    print(f"  Total Regex: {regex_total_time}")
    with open(timing_file, mode="a", newline="") as tf:
        time_writer = csv.writer(tf)
        time_writer.writerow(
            [
                "Total",
                shepherd_total_time,
                labrador_total_time,
                regex_total_time,
            ]
        )


skip_target_list = [
    "mp4dump",
    "imginfo",
    "tcpdump",
    "objdump",
    "readelf",
]


def main():
    if not is_running_in_docker():
        logging.error("This script must be run in a Docker container.")
        exit(1)

    parser = argparse.ArgumentParser(description="Evaluation of BB Inference Precision")
    parser.add_argument(
        "-p",
        "--processes",
        type=int,
        default=cpu_count(),
        help="Number of concurrent processes",
    )
    parser.parse_args()

    target_root = "/work/target"
    target_list = bzc.get_target_list(target_root)
    target_list = [target for target in target_list if target not in skip_target_list]

    print(f"Found {len(target_list)} targets")
    print(target_list)
    for target in target_list:
        process_target(target_root, target)


if __name__ == "__main__":
    main()
