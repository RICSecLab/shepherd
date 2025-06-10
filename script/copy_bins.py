#!/usr/bin/env python3

import sys
import pathlib
import shutil


def main():
    try:
        script_dir = pathlib.Path(__file__).parent.resolve()
    except NameError:
        script_dir = pathlib.Path.cwd()

    put_bin_dir = script_dir.parent / "put_bin"

    target_base_dir = script_dir.parent / "target"

    if not put_bin_dir.is_dir():
        print(f"Error: Source directory not found at '{put_bin_dir}'", file=sys.stderr)
        sys.exit(1)

    print(f"Source directory found: '{put_bin_dir}'")
    print(f"Target base directory: '{target_base_dir}'")
    print("-" * 30)

    error_occurred = False

    for item in put_bin_dir.iterdir():
        if not item.is_dir():
            continue

        sd_name = item.name

        source_file = item / "put_bin"
        target_sd_dir = target_base_dir / sd_name

        if not target_sd_dir.is_dir():
            print(
                f"  - Error: Target directory '{target_sd_dir}' does not exist.",
                file=sys.stderr,
            )
            error_occurred = True
            continue  # Move to the next item

        if not source_file.is_file():
            print(f"  - Error: Source file '{source_file}' not found.", file=sys.stderr)
            error_occurred = True
            continue  # Move to the next item

        destination_file = target_sd_dir / "put_bin"

        try:
            shutil.copy2(source_file, destination_file)
            print(f"Copied '{source_file}' to '{destination_file}'")
        except (IOError, shutil.SameFileError) as e:
            print(f"  - Error: Could not copy file. Reason: {e}", file=sys.stderr)
            error_occurred = True

    print("-" * 30)

    if error_occurred:
        print("Script finished with one or more errors.")
        sys.exit(1)
    else:
        print("Script finished successfully.")


if __name__ == "__main__":
    main()
