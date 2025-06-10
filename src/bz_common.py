from typing import Dict, Tuple
import pickle
import os
import logging
import datetime


# Configure the logger
def setup_logging(enabled=True):
    jst = datetime.timezone(datetime.timedelta(hours=9), "JST")
    if enabled:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logging.Formatter.converter = lambda *args: datetime.datetime.now(
            tz=jst
        ).timetuple()
    else:
        logging.disable(logging.CRITICAL)  # Disables all logging


# load ghidra static analysis result pickle
def load_static_analysis_result(stat_dir: str):
    pickle_path = os.path.join(stat_dir, "pickle_analysis.bin")
    json_path = os.path.join(stat_dir, "CFG_analysis.txt")

    with open(pickle_path, "rb") as f:
        put_cfg = pickle.load(f, encoding="bytes")
    put_cfg.struct_CFG(json_path)

    # Load the edge_idx_map and vertex_idx_map
    edge_idx_map: Dict[Tuple[int, int], int] = {}
    vertex_idx_map: Dict[int, int] = {}
    with open(os.path.join(stat_dir, "edge.txt"), "r") as f:
        idx = 0
        for line in f:
            edge = line.strip().split(" ")
            edge_idx_map[(int(edge[0], 16), int(edge[1], 16))] = idx
            idx += 1
    with open(os.path.join(stat_dir, "vertex.txt"), "r") as f:
        idx = 0
        for line in f:
            vertex = line.strip()
            vertex_idx_map[int(vertex, 16)] = idx
            idx += 1
    return put_cfg, edge_idx_map, vertex_idx_map


def get_target_list(target_dir: str, select_text=None):
    target_list = os.listdir(target_dir)

    skip_target_list = []
    target_list = [t for t in target_list if t not in skip_target_list]
    # If there is "-s" option, read them by splitting with ","
    target_list = select_text.split(",") if select_text else target_list
    target_list.sort()
    return target_list
