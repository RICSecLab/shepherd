from bb_match import BBMatcher, LabradorMatcher
from CFG_recover import BB
from typing import Dict, Tuple, Union, List
from CFG_transform import CFGTransformer
import bz_common as bzc
import os
import hashlib
import sys

# Input byte hash set to avoid duplicate calculation
seen_bytes = set()
seen_vertices = set()
use_labrador_low = False
use_labrador_high = False
vertex_idx_map: Dict[int, int] = {}
# global vars for stats


def read_max_lines_to_read():
    max_lines = 5000  # default; Too long!
    if "FUZZ_MAX_LINES" in os.environ:
        max_lines = int(os.environ["FUZZ_MAX_LINES"])
    return max_lines


# Firstly, read necessary env vars; plus existence checks
def read_env_configs():
    stat_dir_env = "FUZZ_STATIC_ANALYSIS_PATH"
    stat_dir = os.environ.get(stat_dir_env)
    if stat_dir is None:
        raise Exception(f"{stat_dir_env} is not set")

    fuzz_out_dir = os.environ.get("FUZZ_OUT_DIR_PATH")
    if fuzz_out_dir is None:
        raise Exception("FUZZ_OUT_DIR_PATH is not set")

    return stat_dir, fuzz_out_dir


# PUT response is in stdout.txt and stderr.txt
def load_put_response(fuzz_out_dir):
    stdout_file_path = os.path.join(fuzz_out_dir, "stdout.txt")
    stderr_file_path = os.path.join(fuzz_out_dir, "stderr.txt")
    lines = []
    prev_line = None
    with open(stdout_file_path, "rb") as f:
        for line in f:
            if line != prev_line:
                lines.append(line)
            prev_line = line
    prev_line = None
    with open(stderr_file_path, "rb") as f:
        for line in f:
            if line != prev_line:
                lines.append(line)
            prev_line = line
    # return last max_lines lines
    return lines[-max_lines:]


# just read the vertex_idx_map
def calc_vertex_idx(addr):
    assert addr in vertex_idx_map
    return vertex_idx_map[addr]


def save_vertices(bb_list, fuzz_out_dir):
    out_file_path = os.path.join(fuzz_out_dir, "edges.txt")
    with open(out_file_path, "w") as f:
        for bb in bb_list:
            addr = bb.start_addr
            idx = calc_vertex_idx(addr)
            f.write(f"{idx:x}\n")
            seen_vertices.add(addr)


def save_addrs_for_fuzzer(
    addr_list: Union[List[int], List[Tuple[int, int]]], fuzz_out_dir
):
    out_file_path = os.path.join(fuzz_out_dir, "edges.txt")
    with open(out_file_path, "w") as f:
        for addr in addr_list:
            idx = calc_vertex_idx(addr)
            f.write(f"{idx:x}\n")
            seen_vertices.add(addr)


matcher = None


def process_fuzzer_request(put_cfg, fuzz_out_dir):
    lines = load_put_response(fuzz_out_dir)
    whole_bytes = b"".join(lines)
    hashed_bytes = hashlib.sha256(whole_bytes).digest()
    if hashed_bytes in seen_bytes:
        return
    seen_bytes.add(hashed_bytes)

    global matcher
    if use_labrador_high:
        if matcher is None:
            matcher = LabradorMatcher(put_cfg, 0.70)
        bbs = matcher.get_labrador_bbs(whole_bytes)
        addr_list = list(map(lambda x: x.start_addr, bbs))
        save_addrs_for_fuzzer(addr_list, fuzz_out_dir)
        return

    elif use_labrador_low:
        if matcher is None:
            matcher = LabradorMatcher(put_cfg, 0.35)
        bbs = matcher.get_labrador_bbs(whole_bytes)
        addr_list = list(map(lambda x: x.start_addr, bbs))
        save_addrs_for_fuzzer(addr_list, fuzz_out_dir)
    else:
        if matcher is None:
            matcher = BBMatcher(put_cfg)
        bbs = matcher.search_bbs(whole_bytes)
        addr_list = list(map(lambda x: x.start_addr, bbs))
        save_addrs_for_fuzzer(addr_list, fuzz_out_dir)
        return put_cfg, bbs


def save_all_vertices(fuzz_out_dir):
    edge_file_path = os.path.join(fuzz_out_dir, "all_vertices.txt")
    with open(edge_file_path, "w") as f:
        for addr in seen_vertices:
            f.write(f"{addr:x}\n")


def start_fuzz_server(put_cfg, fuzz_out_dir):
    read_fd = 88
    write_fd = 89

    count = 0
    while True:
        count += 1
        print(f"Server is READY: {count}")
        try:
            os.read(read_fd, 4)

            process_fuzzer_request(put_cfg, fuzz_out_dir)

            os.write(write_fd, b"DONE")
        # if there is error, then the fuzzer stopped, we dump the whole coverage
        except Exception as e:
            sys.stderr.write(f"Server: Fuzzer stopped: {e}\n")
            save_all_vertices(fuzz_out_dir)
            break


def main():
    stat_dir, fuzz_out_dir = read_env_configs()
    global vertex_idx_map
    put_cfg, _, vertex_idx_map = bzc.load_static_analysis_result(stat_dir)
    transformer = CFGTransformer(put_cfg)
    transformer.run_all_passes(put_cfg)
    put_cfg.build_dominators()
    put_cfg.build_func_distance_map()

    global max_lines
    max_lines = read_max_lines_to_read()

    global use_labrador_low
    global use_labrador_high
    if "FUZZ_USE_LABRADOR_LOW" in os.environ:
        use_labrador_low = True

    if "FUZZ_USE_LABRADOR_HIGH" in os.environ:
        assert not use_labrador_low, (
            "Cannot use both FUZZ_USE_LABRADOR_LOW and FUZZ_USE_LABRADOR_HIGH"
        )
        use_labrador_high = True

    if "FUZZ_NOT_START_SERVER" in os.environ:
        return process_fuzzer_request(put_cfg, fuzz_out_dir)

    print("Sever: Warming up...")

    start_fuzz_server(put_cfg, fuzz_out_dir)

    """
    for line in lines:
        print(f"response: {line}")
    """

    """
    print("Estimated paths: ")
    for path in estimate_paths:
        print(path)
    """


if __name__ == "__main__":
    main()
