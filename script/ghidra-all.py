import argparse
import os
import subprocess
from multiprocessing import cpu_count

skip_target_list = []


# return sorted
def find_all_subdirs(directory):
    return sorted(
        [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if os.path.isdir(os.path.join(directory, f))
        ]
    )


def process_target(target):
    # Run /ghidra_11.1.1_PUBLIC/support/analyzeHeadless tmp_project tmptarget -deleteProject -import $TARGET_BIN -scriptPath ghidra/ -postScript static_analysis_by_ghidra.py
    target_bin = os.path.join(target, "put_bin")
    cmd = [
        "/ghidra_11.1.1_PUBLIC/support/analyzeHeadless",
        "tmp_project",
        "tmptarget",
        "-deleteProject",
        "-import",
        target_bin,
        "-scriptPath",
        "ghidra/",
        "-postScript",
        "static_analysis_by_ghidra.py",
    ]
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(description="Analyze commands")
    parser.add_argument("target_dir", help="Path to `target` directory")
    parser.add_argument("-p", "--processes", type=int, default=cpu_count())
    args = parser.parse_args()

    targets = find_all_subdirs(args.target_dir)
    print(f"Found {len(targets)} targets")

    for t in targets:
        target_name = t.split("/")[-1]
        if target_name in skip_target_list:
            print(f"Skip {target_name}")
            continue
        os.environ["TARGET_DIR"] = target_name
        process_target(t)

    return


if __name__ == "__main__":
    main()
