import argparse
import os
import shutil
import sys
import fuzz_server
import bz_common as bzc
import time
from collections import defaultdict
from bb_match import BBMatcher, RegexMatcher, augment_must_bbs, aggressive_augment
from CFG_recover import BB
from CFG_transform import CFGTransformer
from typing import Set


def setup_environment(input_file, static_analysis_dir, stderr_file=None):
    if not os.path.isfile(input_file):
        print(f"Error: Input file '{input_file}' does not exist.")
        sys.exit(1)

    if not os.path.isdir(static_analysis_dir):
        print(
            f"Error: Static analysis directory '{static_analysis_dir}' does not exist."
        )
        sys.exit(1)

    tmp_out_dir = "/tmp/tmp_out"
    if os.path.exists(tmp_out_dir):
        shutil.rmtree(tmp_out_dir)
    os.makedirs(tmp_out_dir)

    shutil.copy(input_file, os.path.join(tmp_out_dir, "stdout.txt"))

    if stderr_file:
        if not os.path.isfile(stderr_file):
            print(f"Error: Stderr file '{stderr_file}' does not exist.")
            sys.exit(1)
        shutil.copy(stderr_file, os.path.join(tmp_out_dir, "stderr.txt"))
    else:
        open(os.path.join(tmp_out_dir, "stderr.txt"), "w").close()

    os.environ["FUZZ_OUT_DIR_PATH"] = tmp_out_dir
    os.environ["FUZZ_STATIC_ANALYSIS_PATH"] = static_analysis_dir


def run_main():
    os.environ["FUZZ_NOT_START_SERVER"] = "1"
    return fuzz_server.main()


def print_search_results(label: str, estimated_bbs: Set[BB], real_bbs: Set[BB]):
    tp_bbs = estimated_bbs.intersection(real_bbs)
    fp_bbs = estimated_bbs.difference(real_bbs)
    print(f"{label} BBs: {len(estimated_bbs)}")
    print(f"  TP BBs: {len(tp_bbs)}")
    print(f"  FP BBs: {len(fp_bbs)}")


def analyze_precision(cfg, response: bytes, real_bbs: Set[BB]):
    matcher = BBMatcher(cfg)
    rg_matcher = RegexMatcher(cfg)
    single_match_bbs = set()
    multi_match_bbs = set()
    multi_bb_patterns = set()

    matcher_bb = matcher.search_bbs(response)
    rg_matcher_bb = rg_matcher.search_bbs(response)
    print(f"Matcher BBs: {matcher_bb}")
    print(f"Regex Matcher BBs: {rg_matcher_bb}")
    return

    for pat_idx in matcher.search(response):
        xref = matcher.idx_to_match_info[pat_idx].xref
        parent_funcs = {bb.parent_funcnode for bb in xref.bbs}
        for bb in xref.bbs:
            if len(parent_funcs) == 1:
                single_match_bbs.add(bb)
            else:
                multi_match_bbs.add(bb)
                multi_bb_patterns.add(xref)
    single_match_bbs.union(multi_match_bbs)

    filter_bbs = matcher.search_bbs(response)
    filter_augmented_bbs = augment_must_bbs(filter_bbs)
    aggressive_bbs = aggressive_augment(filter_bbs)

    print_search_results("Estimate-Single  ", single_match_bbs, real_bbs)
    print_search_results("Estimate-Multi   ", multi_match_bbs, real_bbs)
    print_search_results("Filter-No-Augment", filter_bbs, real_bbs)
    print_search_results("Filter-Augmented ", filter_augmented_bbs, real_bbs)
    print_search_results("Aggressive-Augment", aggressive_bbs, real_bbs)

    print(f"Multi-BB Patterns: {len(multi_bb_patterns)}")
    for xref in multi_bb_patterns:
        print(f"  {xref.literal!r}")
        parent_funcs = {bb.parent_funcnode for bb in xref.bbs}
        funcs = sorted(parent_funcs, key=lambda func: func.addr)
        bbs = sorted(xref.bbs, key=lambda bb: bb.start_addr)
        print(f"    {funcs}")

    mtp_bbs = multi_match_bbs.intersection(real_bbs)
    print("Muti-TP BBs:")
    for bb in sorted(list(mtp_bbs), key=lambda bb: bb.start_addr):
        print(f"  {bb}")


def load_response(stdout_file, stderr_file) -> bytes:
    with open(stdout_file, "rb") as f:
        response = f.read()
    if stderr_file:
        with open(stderr_file, "rb") as f:
            response += f.read()
    return response


def main():
    parser = argparse.ArgumentParser(
        description="Setup environment and run fuzzing script."
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the input file")
    parser.add_argument(
        "-s",
        "--static-analysis",
        required=True,
        help="Path to the static analysis directory",
    )
    parser.add_argument(
        "-e",
        "--stderr",
        required=False,
        help="Path to the stderr file (optional)",
    )
    # this does not take any argument, it is just a flag
    parser.add_argument(
        "-p",
        "--pin",
        action="store_true",
        help="Run the fuzzing script with Pin",
    )
    args = parser.parse_args()

    bzc.setup_logging(False)
    setup_environment(args.input, args.static_analysis, args.stderr)
    # if inputt has the form .../responses/*.txt, then we read the .../edges/*.txt
    put_cfg, _, _ = bzc.load_static_analysis_result(args.static_analysis)
    transformer = CFGTransformer(put_cfg)
    transformer.run_all_passes(put_cfg)
    put_cfg.build_dominators()
    put_cfg.build_func_distance_map()

    matcher = BBMatcher(put_cfg)
    rg_matcher = RegexMatcher(put_cfg)

    with open(args.input, "rb") as f:
        response = f.read()

    start = time.perf_counter()
    matcher_bb = matcher.search_bbs(response)
    match_end = time.perf_counter()
    rg_matcher_bb = rg_matcher.search_bbs(response)
    rg_match_end = time.perf_counter()

    matcher_bb = sorted(list(matcher_bb), key=lambda bb: bb.start_addr)
    rg_matcher_bb = sorted(list(rg_matcher_bb), key=lambda bb: bb.start_addr)
    print(f"Matcher BBs: {matcher_bb}")
    print(f"Regex Matcher BBs: {rg_matcher_bb}")

    print(f"Matcher Time: {match_end - start}")
    print(f"Regex Matcher Time: {rg_match_end - match_end}")
    return
    analyze_precision(cfg, response, real_bbs)

    return
    funcnode_bbs = defaultdict(set)
    for bb in marked_bbs:
        funcnode = bb.parent_funcnode
        funcnode_bbs[funcnode.addr].add(bb)

    if not args.pin:
        return

    # cfg varriable is alredy modified; we need to reload the original cfg
    # from the files to fit PIN info to Ghidra BB transitions
    orig_cfg, _, _ = bzc.load_static_analysis_result(args.static_analysis)
    real_bbs: Set[BB] = orig_cfg.convert_edges_to_BBs(edges)

    response = load_response(args.input, args.stderr)
    analyze_precision(cfg, response, real_bbs)

    print("done")


if __name__ == "__main__":
    main()
