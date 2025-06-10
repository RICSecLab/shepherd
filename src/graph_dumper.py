from graphviz import Graph
from graphviz import Digraph
from CFG_recover import Path, CFG, Funcnode, BB
import os
from typing import List, Dict, Set, Tuple
import shutil

_call_flow_graph = Graph(format="svg")
_control_flow_graphs: Dict[int, Digraph] = {}
_estimated: Dict[int, Digraph] = {}


def bb_id(bb):
    if bb.score == 0:
        return f"{bb.start_addr:x}"
    return f"{bb.start_addr:x}@{bb.score}"


def init_graph(cfg: CFG):
    for funcnode in cfg.funcnode_dict.values():
        _call_flow_graph.node(hex(funcnode.addr))
        dg = Digraph(format="svg")
        dg.attr(ratio="compact")
        dg.attr(pack="true")
        dg.attr(constraint="false")
        dg.attr(newrank="true")
        for bb in funcnode.BBs.values():
            shape = "doublecircle" if bb.score > 0 else "ellipse"
            dg.node(bb_id(bb), shape=shape)
            dg.attr(rankdir="LR")
        for bb in funcnode.BBs.values():
            for dst in bb.dst_bbs:
                dg.edge(bb_id(bb), bb_id(dst))
        _control_flow_graphs[funcnode.addr] = dg
    for funcnode in cfg.funcnode_dict.values():
        for callee in funcnode.call_func:
            _call_flow_graph.edge(hex(funcnode.addr), hex(callee.addr))


def make_graph(cfg: CFG, skip_edges: Set[Tuple[int, int]]):
    control_graphs = {}
    for funcnode in cfg.funcnode_dict.values():
        dg = Digraph(format="svg")
        dg.attr(ratio="compact")
        dg.attr(pack="true")
        dg.attr(constraint="false")
        dg.attr(newrank="true")
        for bb in funcnode.BBs.values():
            shape = "doublecircle" if bb.score > 0 else "ellipse"
            dg.node(bb_id(bb), shape=shape)
            dg.attr(rankdir="LR")
        for bb in funcnode.BBs.values():
            for dst in bb.dst_bbs:
                if (bb.start_addr, dst.start_addr) in skip_edges:
                    continue
                dg.edge(bb_id(bb), bb_id(dst))
        control_graphs[funcnode.addr] = dg
    return control_graphs


def dump():
    if not os.path.exists("./logs/graphs"):
        os.mkdir("./logs/graphs")
    _call_flow_graph.render("./logs/graphs/call_flow_graph")

    for dg in _control_flow_graphs.keys():
        _control_flow_graphs[dg].render(f"./logs/graphs/CFG_{hex(dg)}")


def clean_dir(dir_path: str):
    if os.path.exists(dir_path):
        shutil.rmtree(dir_path)
    os.makedirs(dir_path)


def draw_edge(
    cfg: CFG, control_graphs, estimate_path: List[Path], destination_dir: str = ""
):
    clean_dir(f"./logs/graphs/{destination_dir}")

    for path in estimate_path:
        func_addr = path.bbs[0].parent_funcnode.addr
        dg: Digraph = control_graphs[func_addr].copy()  # type: ignore
        for bb in path.bbs:
            dg.node(bb_id(bb), style="", color="red", fontcolor="red")
        for edge in path._edges:
            dg.edge(bb_id(edge.bb1), bb_id(edge.bb2), color="red")
        # _estimated[path.bbs[0].parent_funcnode.addr] = dg
        dg.render(
            f"./logs/graphs/{destination_dir}/CFG_{hex(path.bbs[0].parent_funcnode.addr)}"
        )


def draw_true_edge(cfg: CFG, estimate_path: List[Path], destination_dir: str = ""):
    if not os.path.exists(f"./logs/graphs/{destination_dir}"):
        os.makedirs(f"./logs/graphs/{destination_dir}")

    for path in estimate_path:
        if path.bbs[0].parent_funcnode.addr in _estimated.keys():
            dg = _estimated[path.bbs[0].parent_funcnode.addr]
        else:
            dg: Digraph = _control_flow_graphs[path.bbs[0].parent_funcnode.addr].copy()  # type: ignore
        for bb in path.bbs:
            dg.node(hex(bb.start_addr), style="", color="blue")
        for edge in path._edges:
            dg.edge(hex(edge.bb1.start_addr), hex(edge.bb2.start_addr), color="blue")
        dg.render(
            f"./logs/graphs/{destination_dir}/CFG_{hex(path.bbs[0].parent_funcnode.addr)}"
        )


# This is independent of the other drawing stuff
# General purpose function to visualize a function node
def visualize_funcnode(
    funcnode: Funcnode,
    interesting_nodes: Set[BB],
    interesting_funcs: Set[Funcnode],
    filename: str,
):
    func_bbs = funcnode.get_bbs()

    max_nodes = 80
    if len(func_bbs) > max_nodes:
        print(
            f"  {funcnode.addr:x}: Too many nodes to visualize ({len(func_bbs)} > {max_nodes})"
        )
        return
    if len(func_bbs) > 30:
        print(f"  {funcnode.addr:x}: Visualizing {len(func_bbs)} nodes: BIG")

    dot = Digraph()
    dot.attr("graph", rankdir="LR")

    # Add nodes
    for bb in func_bbs:
        label = f"{hex(bb.start_addr)}"
        xlabel = ""
        # label contains the string that this bb refers to
        for xref in bb.xrefs:
            # Remove b'' from the string
            literal = f"{xref.literal!r}"[2:-1]
            # Only the first line
            literal = literal.split("\n")[0].strip()
            if literal[-2:] == "\\n":
                literal = literal[:-2]
            literal = literal[:20]
            # Bunch of escaping for graphviz
            literal.replace("%", "%%")

            xlabel += f"\n{literal}"
        for f in bb.call_func:
            if f in interesting_funcs:
                xlabel += f"\nC {f.addr:x}"
        label = '"' + label + xlabel + '"'
        # Color the interesting nodes
        if bb in interesting_nodes:
            dot.node(str(bb.start_addr), label=label, color="red", style="filled")
        else:
            dot.node(str(bb.start_addr), label)

    # Add edges
    for bb in func_bbs:
        for succ in bb.dst_bbs:
            if len(bb.edge_implicate_bbs[succ]) > 0:
                implicated_bbs = bb.edge_implicate_bbs[succ]
                implication_text = f"{implicated_bbs}"
            else:
                implication_text = ""
            dot.edge(str(bb.start_addr), str(succ.start_addr), label=implication_text)

    dot.render(filename, format="svg", cleanup=True)
