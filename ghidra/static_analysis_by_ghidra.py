# -*- coding: utf-8 -*-
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
import pickle
import json
import os
import sys

sys.path.append("/work/src")
from CFG_recover import CFG, XREF

cfg = CFG()

funcnode_dict = {}
# {"call_func": [], "BBs": {}, "xrefs":[]}
# {"dst_bbs": [], "call_func": [], "xrefs":[], "end_addr": None, "parent_funcnode": None}

fm = currentProgram().getFunctionManager()
functions = fm.getFunctions(True)
bbm = BasicBlockModel(currentProgram())
elf_base = currentProgram().getImageBase().getOffset()
print(f"elf_base: {hex(elf_base)}")


def register_func_and_bbs():
    vertex_list = []
    global funcnode_dict
    for func in functions:
        func_addr = func.getEntryPoint().getUnsignedOffset()
        assert func_addr not in funcnode_dict, "Function should be fresh"
        funcnode = {"call_func": set(), "BBs": {}, "xrefs": set()}
        funcnode_dict[func_addr] = funcnode

        blocks = bbm.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
        for block in blocks:
            bb_addr = block.getFirstStartAddress().getOffset()
            bb_end_addr = block.getLastRange().getMaxAddress().getOffset()
            assert bb_addr not in funcnode["BBs"], "BB should be fresh"
            funcnode_dict[func_addr]["BBs"][bb_addr] = {
                "dst_bbs": set(),
                "call_func": set(),
                "xrefs": set(),
                "end_addr": bb_end_addr,
                "parent_funcnode": func_addr,
            }
            vertex_list.append(bb_addr)
    return vertex_list


def add_bb_connections():
    edge_list = []
    global funcnode_dict
    for func in fm.getFunctions(True):
        func_addr = func.getEntryPoint().getUnsignedOffset()
        funcnode = funcnode_dict[func_addr]
        blocks = bbm.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY)
        for block in blocks:
            bb_addr = block.getFirstStartAddress().getOffset()
            bb = funcnode["BBs"][bb_addr]
            destinations = block.getDestinations(TaskMonitor.DUMMY)
            while destinations.hasNext():
                dst = destinations.next()
                dst_addr = dst.getDestinationAddress().getOffset()
                if dst.getFlowType().isCall():  # explicit call
                    if dst_addr not in funcnode_dict:  # call to weird address
                        print(f"Weird Call : {hex(bb_addr)} -> {hex(dst_addr)}")
                        continue
                    dst_func = funcnode_dict[dst_addr]
                    # funcnodeから呼び出される関数として追加
                    funcnode["call_func"].add(dst_addr)
                    bb["call_func"].add(dst_addr)
                    dst_func["xrefs"].add(bb_addr)
                else:  # non-call instructions such as jmp, jnz, etc.
                    if dst_addr not in funcnode["BBs"]:  # goto another function
                        if dst_addr not in funcnode_dict:  # jump to weird address
                            print(f"Weird Jump : {hex(bb_addr)} -> {hex(dst_addr)}")
                            continue
                        # otherwise we assume this is optimized tail-call
                        dst_func = funcnode_dict[dst_addr]
                        funcnode["call_func"].add(dst_addr)
                        bb["call_func"].add(dst_addr)
                        dst_func["xrefs"].add(bb_addr)
                        continue
                    dst_bb = funcnode["BBs"][dst_addr]
                    bb["dst_bbs"].add(dst_addr)
                    dst_bb["xrefs"].add(dst_addr)
                    edge_list.append((bb_addr, dst_addr))
    return edge_list


# Verify uniquness of each BB and dst_bbs
def verify_funcnode():
    all_bbs = []
    for func_addr, funcnode in funcnode_dict.items():
        all_bbs += list(funcnode["BBs"].keys())
        for bb in funcnode["BBs"].values():
            assert bb["end_addr"] is not None, "BB should have end_addr"
            assert (
                bb["parent_funcnode"] == func_addr
            ), "BB should have correct parent function"
    assert len(all_bbs) == len(set(all_bbs)), "BBs should have unique parent function"


vertex_list = register_func_and_bbs()
edge_list = add_bb_connections()
verify_funcnode()

print(f"Total Vertices: {len(vertex_list)}")
print(f"Total Edges: {len(edge_list)}")

target = os.environ.get("TARGET_BIN")

# Obtain .rodata offset and size
rodata_mem = getMemoryBlock(".rodata")
rodata_addr = rodata_mem.getStart().getOffset()
rodata_size = rodata_mem.getSize()
rodata = getBytes(
    toAddr(rodata_addr), rodata_size
)  # convert Jython array to Python list
# convert list to bytes
rodata = bytes([c + 256 if c < 0 else c for c in rodata])

if not len(rodata) == rodata_size:
    print("Invalid size: rodata")
    exit(0)

saved_xrefs = []  # list of (byte_addr, xref_addr)
cur_block_addr = 0
ff_addr_set = set()
for offset in range(0, rodata_size):
    addr = offset + rodata_addr
    refs = getReferencesTo(toAddr(addr))
    if len(refs) > 0:
        for ref in refs:
            ref_addr = int(ref.getFromAddress().getOffset())
            saved_xrefs.append((addr, ref_addr))

    c = rodata[offset]
    if c >= 0xC0:
        ff_addr_set.add(addr)
        # NOTE: pretty much ad-hoc heuristic to detect jump table byte pattern
        # if addr - (1, 4, 5, 8, 9) in ff_addr_set it's likely to be jump table
        if addr - 9 >= cur_block_addr and {
            addr - 1,
            addr - 4,
            addr - 5,
            addr - 8,
            addr - 9,
        }.issubset(ff_addr_set):
            saved_xrefs = []
    if c == 0:  # we found string terminator! Build the actual bytes
        for byte_addr, xref_addr in saved_xrefs:
            byte_start_offset = byte_addr - rodata_addr
            ref_bytes = rodata[byte_start_offset:offset]
            if len(ref_bytes) < 4:  # skip string literals shorter than 4
                continue
            # skip bytes that is composed of only space and newline
            if all([c in [0x20, 0x0A] for c in ref_bytes]):
                continue
            bbs = list(
                bbm.getCodeBlocksContaining(toAddr(xref_addr), TaskMonitor.DUMMY)
            )
            func = fm.getFunctionContaining(toAddr(xref_addr))
            if bbs and func:
                bb = bbs[0]
                bb_addr = bb.getFirstStartAddress().getOffset()
                func_addr = func.getEntryPoint().getOffset()
                if ref_bytes not in cfg.string_xref.keys():
                    cfg.string_xref[ref_bytes] = XREF(ref_bytes)
                cfg.string_xref[ref_bytes].ro_addrs.add(byte_addr)
                cfg.string_xref[ref_bytes].funcnodes.add(func_addr)
                cfg.string_xref[ref_bytes].bbs.add(bb_addr)

            # print(f"{ref_bytes} referenced by {hex(xref_addr)}")
        saved_xrefs = []
        cur_block_addr = addr + 1

if target:
    target_filename = currentProgram().getExecutablePath().split("/")[-1]
else:
    target_filename = os.environ["TARGET_DIR"]

out_dir = f"static-analysis-result/{target_filename}"
# if not static-analysis-result dir, then make it
if not os.path.exists("static-analysis-result"):
    os.makedirs("static-analysis-result", exist_ok=True)

os.makedirs(out_dir, exist_ok=True)

CFG_file = f"{out_dir}/CFG_analysis.txt"
pickle_file = f"{out_dir}/pickle_analysis.bin"
baseaddr_file = f"{out_dir}/baseaddr.txt"
vertex_file = f"{out_dir}/vertex.txt"
edge_file = f"{out_dir}/edge.txt"


def custom_serializer(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj


with open(CFG_file, "w") as f:
    f.write(json.dumps(funcnode_dict, default=custom_serializer))

with open(pickle_file, "wb") as f:
    pickle.dump(cfg, f)

with open(baseaddr_file, "w") as f:
    f.write(hex(elf_base))

with open(vertex_file, "w") as f:
    f.write("\n".join([hex(v) for v in vertex_list]))
with open(edge_file, "w") as f:
    f.write("\n".join([f"{hex(src)} {hex(dst)}" for src, dst in edge_list]))

# bbm = BasicBlockModel(currentProgram)
# blocks = bbm.getCodeBlocks(TaskMonitor.DUMMY)

# for block in blocks:
#
#     dst_iter = block.getDestinations(TaskMonitor.DUMMY)
#     for dst in dst_iter:
