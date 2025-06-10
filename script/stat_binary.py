#!/usr/bin/python3
import re
import os
import sys
import csv
import argparse
import pandas as pd

# import CFG_recover from "$PWD/../src/CFG_recover.py"
pwd = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(pwd, "..", "src"))
import bz_common as bzc  # noqa E402
import labrador_coverage as lc

pattern = rb"""
        %                   # Literal percent sign
        [0 #+-]?            # Optional flags
        [0-9*]*             # Optional width (digit or *)
        \.?                 # Optional dot
        \d*                 # Optional precision
        [hl]{0,2}           # Optional length modifier
        [jztL]?             # Optional size modifier
        [diuoxXeEfgGaAcpsSn%] # Conversion type
    """


def bytes_is_ascii(b):
    return all(0 <= x < 128 for x in b)


def analyze_target(target):
    similarity_file = os.path.join(output_dir, "similarity", f"{target}.txt")
    substr_file = os.path.join(output_dir, "substr", f"{target}.txt")
    # only take 1 arg
    stat_dir = os.path.join(script_dir, "..", "static-analysis-result", target)
    cfg, _, _ = bzc.load_static_analysis_result(stat_dir)

    # filter the xrefs where the string is only ascii
    cfg.string_xref = {
        k: v for k, v in cfg.string_xref.items() if bytes_is_ascii(v.literal)
    }

    regex = re.compile(pattern, re.VERBOSE)

    multi_count = 0

    format_count = 0

    num_xrefs = len(cfg.string_xref)
    for xref in cfg.string_xref.values():
        literal = xref.literal
        if regex.search(literal):
            format_count += 1

        funcs = {bb.parent_funcnode for bb in xref.bbs}
        if len(funcs) > 1:
            multi_count += 1
        func_text = ", ".join([f"{x.addr:x}" for x in funcs])

        ro_addrs = list(xref.ro_addrs)
        addr_text = ", ".join([f"{x:x}" for x in ro_addrs])
        # print(f"{literal} : {len(xref.bbs)}, [{addr_text}], <{func_text}>")

    multi_ratio = multi_count / num_xrefs
    format_ratio = format_count / num_xrefs

    literals = {x.literal for x in cfg.string_xref.values()}
    # sort by length
    literals = sorted(literals, key=len)
    # Find strings that is substring of the other
    similar_low_count = 0
    similar_high_count = 0
    for i, l in enumerate(literals):
        low_incresed = False
        for j in range(i + 1, len(literals)):
            sim = lc._SIM(l, literals[j])
            if sim > 0.35 and not low_incresed:
                similar_low_count += 1
                low_incresed = True
            if sim > 0.8:
                similar_high_count += 1
                break
    similar_low_ratio = similar_low_count / num_xrefs
    similar_high_ratio = similar_high_count / num_xrefs

    substr_count = 0
    with open(substr_file, "w") as f:
        for i, l in enumerate(literals):
            for j in range(i + 1, len(literals)):
                if l in literals[j]:
                    substr_count += 1
                    # print(f"{l}, {literals[j]}")
                    f.write(f"{l}, {literals[j]}\n")
                    break

    substr_ratio = substr_count / num_xrefs

    with open(stat_file, mode="a", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [
                target,
                multi_count,
                format_count,
                similar_low_count,
                similar_high_count,
                substr_count,
                num_xrefs,
            ]
        )


def csv_to_latex():
    df = pd.read_csv(stat_file)
    df = df.sort_values("Target")
    # target_max_len is the max len after replacing _ with \_
    target_max_len = df["Target"].apply(lambda x: len(x.replace("_", "\\_"))).max()
    for _, row in df.iterrows():
        target = row["Target"]
        target = target.replace("_", "\\_")
        total = row["Total"]
        similar_low = row["LowSimilar"] / total
        similar_high = row["HighSimilar"] / total
        MultiFunc = row["MultiFunc"] / total
        Format = row["Format"] / total
        print(
            f"{target: <{target_max_len}} & {total:4} & {similar_low:.2f} & {similar_high:.2f} & {MultiFunc:.2f} & {Format:.2f} \\\\"
        )
    print(r"\hline")


def main():
    parser = argparse.ArgumentParser("Analyze embedded string characteristics.")
    parser.add_argument(
        "-f", "--formatter", help="Convert the csv to latex table", action="store_true"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="/dev/shm/binary_stats",
        help="Directory to save analysis results",
    )

    args = parser.parse_args()
    global output_dir
    output_dir = args.output_dir
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    global stat_file
    stat_file = os.path.join(output_dir, "stat.csv")

    if args.formatter:
        csv_to_latex()
        return
    # create empty file
    with open(stat_file, "w", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(
            [
                "Target",
                "MultiFunc",
                "Format",
                "LowSimilar",
                "HighSimilar",
                "Substr",
                "Total",
            ]
        )

    global script_dir
    script_dir = os.path.dirname(os.path.realpath(__file__))
    target_dir = os.path.join(script_dir, "..", "target")
    target_list = bzc.get_target_list(target_dir)
    similarity_dir = os.path.join(output_dir, "similarity")
    substr_dir = os.path.join(output_dir, "substr")
    os.makedirs(similarity_dir, exist_ok=True)
    os.makedirs(substr_dir, exist_ok=True)
    print(f"Target list: {target_list}")
    for target in target_list:
        print(f"Analyzing {target}")
        analyze_target(target)


if __name__ == "__main__":
    main()
