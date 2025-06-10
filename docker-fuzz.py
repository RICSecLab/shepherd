#!/usr/bin/python3
import argparse
import os
import sys


def set_env_vars(put_filename):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    stat_analysis_dir = os.path.join(cur_dir, "static-analysis-result", put_filename)
    shepherd_path = os.path.join(cur_dir, "src", "fuzz_server.py")
    os.environ["FUZZ_STATIC_ANALYSIS_PATH"] = stat_analysis_dir
    os.environ["FUZZ_SHEPHERD_PATH"] = shepherd_path
    os.environ["AFL_NO_FORKSRV"] = "1"
    os.environ["AFL_SKIP_BIN_CHECK"] = "1"

    # check if stat_analysis_dir exists, if not error
    if not os.path.exists(stat_analysis_dir):
        sys.stderr.write(f"Error: {stat_analysis_dir} does not exist\n")
        sys.stderr.write(f"Run 'ghidra/analyze.sh /path/to/put' first\n")
        sys.exit(1)


# check if exists
def get_afl_fuzz_path():
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    afl_fuzz_path = os.path.join(cur_dir, "AFLplusplus", "afl-fuzz")
    if not os.path.exists(afl_fuzz_path):
        sys.stderr.write(f"Error: {afl_fuzz_path} does not exist\n")
        sys.stderr.write(f"  Build AFL++ first\n")
        sys.exit(1)
    return afl_fuzz_path


def get_afl_cmd(afl_bin, args, afl_args, seed_dir, out_dir_path):
    cmd = [afl_bin, "-m", "none", "-i", seed_dir, "-o", out_dir_path]
    if args.timeout:
        cmd.extend(["-t", str(args.timeout)])
    cmd.append("--")
    cmd.extend(afl_args)
    return cmd


def get_afl_args(target_dir):
    cmd_file_path = os.path.join(target_dir, "cmd.sh")
    with open(cmd_file_path, "r") as f:
        cmd = f.read().strip()
    put_bin_path = os.path.join(target_dir, "put_bin")
    # replace $PUT_BIN with actual bin path
    cmd = cmd.replace("$PUT_BIN", put_bin_path)
    return cmd.split()


def unpack_seeds(target_dir):
    target_name = os.path.basename(target_dir)
    # the seed file is target_dir/seed.zip
    seed_zip = os.path.join(target_dir, "seed.zip")
    # the output dir is /tmp/seeds/target_name
    output_dir = os.path.join("/tmp/seeds", target_name)
    if os.path.exists(output_dir):
        print(f"Seeds already unpacked in {output_dir}")
        return output_dir
    os.makedirs(output_dir, exist_ok=True)
    print(f"Unpacking {seed_zip} to {output_dir}")
    os.system(f"unzip -q {seed_zip} -d {output_dir}")
    return output_dir


def main():
    parser = argparse.ArgumentParser(description="Fuzz")
    parser.add_argument("putname", help="Name of the put in target")
    parser.add_argument("-t", "--timeout", type=int, help="timeout in ms")
    # b and l are mutually exclusive
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-b", "--baseline", action="store_true")
    group.add_argument("-l", "--labrador", action="store_true")

    args = parser.parse_args()

    put_name = args.putname
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    target_dir = os.path.join(cur_dir, "target", put_name)

    afl_args = get_afl_args(target_dir)

    if args.baseline:
        os.environ["FUZZ_BASELINE"] = "1"
    if args.labrador:
        os.environ["FUZZ_USE_LABRADOR_LOW"] = "1"
    put_path = afl_args[0]

    set_env_vars(put_name)
    afl_bin = get_afl_fuzz_path()
    seed_dir = unpack_seeds(target_dir)

    if args.baseline:
        out_dir_name = f"{put_name}-base"
    elif args.labrador:
        out_dir_name = f"{put_name}-lab"
    else:
        out_dir_name = put_name

    output_base_dir = os.environ.get("SHEPHERD_OUTPUT_DIR", "/dev/shm/output")
    out_dir_path = os.path.join(output_base_dir, out_dir_name)

    afl_cmd = get_afl_cmd(afl_bin, args, afl_args, seed_dir, out_dir_path)

    # run fuzz
    os.execv(afl_bin, afl_cmd)

    return


if __name__ == "__main__":
    main()
