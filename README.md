# Shepherd: High-Precision Coverage Inference for Response-guided Blackbox Fuzzing

This repository contains the artifact for the paper "Shepherd: High-Precision Coverage Inference for Response-guided Blackbox Fuzzing". Shepherd is a novel coverage inference method that combines high-precision string matching with context analysis to improve the accuracy of coverage estimation in blackbox fuzzing environments.

## Overview

The core components of Shepherd are:
*   **High-Precision Matching Algorithm**: Utilizes the Aho-Corasick algorithm for exact and efficient string matching, an abstraction layer for format strings, and a longest-match strategy. This reduces both over-estimation (from similar strings) and under-estimation (from dynamic format strings).
*   **Context-Driven Block Identification**: Leverages the context of observed strings in the program's output and the control-flow graph (CFG) to resolve ambiguities when a single string is referenced by multiple code blocks.

This artifact provides the tools and scripts to reproduce the experiments from the paper, as well as to run the Shepherd-enhanced fuzzer on new targets.

## Repository Structure

The repository is organized as follows:

```
└── shepherd/
    ├── aflpp_patch/      # Patch for AFL++ to integrate Shepherd
    ├── bin_builder/      # Scripts to build the target programs
    ├── ghidra/           # Ghidra scripts for static analysis
    ├── pintools/         # Intel Pin tool for collecting ground truth coverage
    ├── script/           # Scripts for running experiments and plotting results
    ├── src/              # Source code for the Shepherd inference engine
    ├── target/           # Target programs for evaluation (populated by build scripts)
    ├── tests/            # Unit tests
    ├── Dockerfile.fuzz   # Dockerfile for the fuzzer and experiment environment
    ├── README.md         # This file
    └── ...
```

## Prerequisites

The recommended way to use this artifact is through Docker, which ensures a consistent and reproducible environment.
*   **Docker**: [https://www.docker.com/get-started](https://www.docker.com/get-started)

## Getting Started: Building the Target Binaries

The `target/` directory ships with the necessary configuration files (`cmd.sh`, `seed.zip`) for each program, but the executable binaries (`put_bin`) must be built first.

### Step 1: Build the Target Binaries

Run the builder script. This will use a Docker container to compile all target programs. The resulting binaries will be placed in a new `put_bin/` directory at the root of the project.

```bash
./bin_builder/run.sh
```

### Step 2: Copy Binaries into Place

Run the copy script. This moves the compiled binaries from the `put_bin/` directory into their respective `target/<program_name>/` subdirectories.

```bash
./script/copy_bins.py
```

After these steps, each subdirectory in `target/` will contain the required `put_bin` executable, and you can proceed with the experiments.

## Experiment Reproduction

*Note: Ensure you have completed the "Getting Started" section above before proceeding.*

Follow these steps to reproduce the precision and overhead evaluation results presented in the paper.

### Step 1: Perform Static Analysis

First, run the static analysis on all target programs. This script uses Ghidra to extract the CFG, string references, and other necessary metadata from the binaries you just built. This is a one-time setup step.

```bash
# This will build a Ghidra Docker image and analyze all binaries in target/
./ghidra/analyze-all.sh
```
The analysis results will be stored in the `static-analysis-result/` directory.

### Step 2: Evaluate Precision and Overhead

Next, run the main evaluation script. This script will:
1.  Execute each target with predefined seed inputs.
2.  Collect ground truth coverage using an included Intel Pin tool.
3.  Run Shepherd and other comparison methods (Labrador, Regex) on the program's output.
4.  Measure precision, recall, F1-score, and inference time for each method.

```bash
# Run the evaluation. Results will be saved to /dev/shm/rgf_precision.
# You can specify a different output directory if needed.
./eval_precision.sh /dev/shm/rgf_precision
```
The results will be saved in the specified output directory (e.g., `/dev/shm/rgf_precision`), organized into two subdirectories:
*   `precision/`: Contains raw CSV files with precision, recall, and F1 scores per seed.
*   `time/`: Contains raw CSV files with inference timing data per seed.

### Step 3: Generate Result Plots and Tables

After the evaluation is complete, you can generate the summary table and plot from the paper.

*   **Generate Precision Summary Table:**
    This script aggregates the data from the `precision/` directory and prints a final CSV-formatted table to standard output, summarizing the metrics for each inference method.

    ```bash
    python3 script/precision_stat.py /dev/shm/rgf_precision/precision
    ```

*   **Generate Overhead Cactus Plot:**
    This script uses the data from the `time/` directory to generate a cactus plot (`cactus_plot.svg`) that visualizes the inference overhead of each method.

    ```bash
    python3 script/plot_overhead.py /dev/shm/rgf_precision/time
    ```

## Fuzzing with Shepherd

You can also use Shepherd to fuzz the provided targets or add your own.

### 1. Start the Fuzzing Container

The `test.sh` script builds the fuzzing environment and starts an interactive bash session inside the container.

```bash
./test.sh
```

### 2. Run the Fuzzer

Inside the container, you can start a fuzzing campaign using the `docker-fuzz.py` script. You must specify the target's name, which corresponds to a subdirectory in the `target/` directory.

```bash
# Usage: ./docker-fuzz.py [TARGET_NAME] [options]

# Example: Fuzz the 'exif' target with Shepherd
./docker-fuzz.py exif

# Example: Fuzz 'exif' with Labrador for comparison
./docker-fuzz.py exif --labrador

# Example: Fuzz 'exif' in baseline blackbox mode
./docker-fuzz.py exif --baseline
```
Fuzzing results will be saved to a directory on the host machine (defaults to `/dev/shm/fuzzer-output`, which can be changed in `test.sh`).

### 3. Adding a New Target

To fuzz a new program with Shepherd:

1.  **Create a Directory for the Target**:
    ```bash
    mkdir target/my_new_target
    ```

2.  **Add Required Files** to `target/my_new_target/`:
    *   `put_bin`: The target binary. You must provide your own compiled binary.
    *   `cmd.sh`: A script specifying the command-line for the target (e.g., `$PUT_BIN -d @@`).
    *   `seed.zip`: A zip archive containing initial seed inputs.

3.  **Perform Static Analysis**:
    From the host, run the Ghidra analysis on your new binary.
    ```bash
    ./ghidra/analyze.sh ./target/my_new_target/put_bin
    ```

4.  **Start Fuzzing**:
    Start the container with `./test.sh` and run the fuzzer on your new target.
    ```bash
    # Inside the container
    ./docker-fuzz.py my_new_target
    ```

## Citation
If you use Shepherd in your research, please cite our paper:
```bibtex
@inproceedings{10.1145/3713081.3731719,
    author = {Shimizu, Takuya and Yoshizawa, Ryuichi and Otsuka, Kaoru and Fujiwara, Yudai and Sugiyama, Yuichi},
    title = {Shepherd: High-Precision Coverage Inference for Response-guided Blackbox Fuzzing (Registered Report)},
    year = {2025},
    isbn = {9798400714740},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    url = {https://doi.org/10.1145/3713081.3731719},
    doi = {10.1145/3713081.3731719},
    booktitle = {Proceedings of the 34th ACM SIGSOFT International Symposium on Software Testing and Analysis},
    pages = {105–115},
    numpages = {11},
    keywords = {fuzzing, blackbox fuzzing, greybox fuzzing, coverage inference, software security, vulnerability detection},
    location = {Clarion Hotel Trondheim, Trondheim, Norway},
    series = {ISSTA Companion '25}
}
```
