import os
import glob
import math
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.lines as mlines

# Configuration variables
COLS = 4
USE_LOG_SCALE = False  # Set to True to use logarithmic scales for the y-axis in plots

# Font size configuration
TITLE_FONT_SIZE = 22
AXIS_LABEL_FONT_SIZE = 20
LEGEND_FONT_SIZE = 24
TICK_LABEL_FONT_SIZE = 20
MARKER_SIZE = 16
CACTUS_MARKER_SIZE = 2
CACTUS_LINEWIDTH = 4


def plot_cactus(csv_files, use_log_scale=USE_LOG_SCALE):
    """
    Generates a grid of cactus plots, one per CSV file (target).
    For each target, the x-axis represents the number of benchmarks solved,
    and the y-axis shows the cumulative total time (in seconds) for each algorithm:
    Shepherd, Labrador, and Regex.
    """
    num_files = len(csv_files)
    rows = math.ceil(num_files / COLS)
    fig, axes = plt.subplots(rows, COLS, figsize=(6 * COLS, 5 * rows))

    if isinstance(axes, np.ndarray):
        axes = axes.flatten()
    else:
        axes = [axes]

    for i, csv_file in enumerate(csv_files):
        df = pd.read_csv(csv_file)
        df = df.iloc[:-1]  # Remove the total row

        experiment_name = os.path.splitext(os.path.basename(csv_file))[0]

        shepherd_times = df.iloc[:, 1].tolist()
        labrador_times = df.iloc[:, 2].tolist()
        regex_times = df.iloc[:, 3].tolist()

        shepherd_cumsum = np.cumsum(shepherd_times)
        labrador_cumsum = np.cumsum(labrador_times)
        regex_cumsum = np.cumsum(regex_times)

        counts_shepherd = np.arange(1, len(shepherd_times) + 1)
        counts_labrador = np.arange(1, len(labrador_times) + 1)
        counts_regex = np.arange(1, len(regex_times) + 1)

        ax = axes[i]
        marker_opts = {
            "marker": "o",
            "markersize": CACTUS_MARKER_SIZE,
            "linewidth": CACTUS_LINEWIDTH,
        }

        ax.plot(
            counts_shepherd,
            shepherd_cumsum,
            drawstyle="steps-post",
            linestyle="-",
            color="red",
            label="Shepherd",
            **marker_opts,
        )
        ax.plot(
            counts_labrador,
            labrador_cumsum,
            drawstyle="steps-post",
            linestyle="-",
            color="blue",
            label="Labrador-L",
            **marker_opts,
        )
        ax.plot(
            counts_regex,
            regex_cumsum,
            drawstyle="steps-post",
            linestyle="-",
            color="green",
            label="Regex",
            **marker_opts,
        )

        ax.set_xlabel("Number of Benchmarks Solved", fontsize=AXIS_LABEL_FONT_SIZE)
        ax.set_ylabel("Cumulative Time (sec)", fontsize=AXIS_LABEL_FONT_SIZE)
        if use_log_scale:
            ax.set_yscale("log")
        if experiment_name == "libpng_read_fuzzer":
            experiment_name = "libpng_read"
        ax.set_title(experiment_name, fontsize=TITLE_FONT_SIZE)
        ax.tick_params(labelsize=TICK_LABEL_FONT_SIZE)
        ax.grid(True, linestyle="--", alpha=0.6)

    for j in range(i + 1, len(axes)):
        fig.delaxes(axes[j])

    shepherd_handle = mlines.Line2D(
        [],
        [],
        color="red",
        marker="o",
        linestyle="-",
        markersize=MARKER_SIZE,
        label="Shepherd",
    )
    labrador_handle = mlines.Line2D(
        [],
        [],
        color="blue",
        marker="o",
        linestyle="-",
        markersize=MARKER_SIZE,
        label="Labrador-L",
    )
    regex_handle = mlines.Line2D(
        [],
        [],
        color="green",
        marker="o",
        linestyle="-",
        markersize=MARKER_SIZE,
        label="Regex",
    )
    fig.legend(
        handles=[shepherd_handle, labrador_handle, regex_handle],
        loc="upper center",
        ncol=3,
        fontsize=LEGEND_FONT_SIZE,
        frameon=False,
    )

    fig.tight_layout(rect=[0, 0, 1, 0.93])
    output_filename = "cactus_plot.svg"
    plt.savefig(output_filename)
    plt.close(fig)
    print(f"Saved {output_filename}")


def main(data_folder):
    csv_files = glob.glob(os.path.join(data_folder, "*.csv"))
    if not csv_files:
        raise ValueError(f"No CSV files found in the specified folder: {data_folder}")

    csv_files.sort(key=lambda f: os.path.splitext(os.path.basename(f))[0])

    plot_cactus(csv_files, use_log_scale=USE_LOG_SCALE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate cactus plot images from CSV files."
    )
    parser.add_argument(
        "data_folder", type=str, help="Directory containing the CSV files"
    )
    args = parser.parse_args()
    main(args.data_folder)
