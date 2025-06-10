#!/usr/bin/python3
import pandas as pd
import os
import sys


def calculate_and_print_csv(directory_path):
    """
    Calculates precision, recall, and F1 score for each CSV file in a directory
    and prints the aggregated results as a single CSV table to standard output.
    """
    # Check if the provided path is a valid directory.
    if not os.path.isdir(directory_path):
        print(f"Error: {directory_path} is not a valid directory.", file=sys.stderr)
        return

    all_metrics = []

    # Iterate through each .csv file in the directory
    files = sorted([f for f in os.listdir(directory_path) if f.endswith(".csv")])

    for file_name in files:
        file_path = os.path.join(directory_path, file_name)
        try:
            df = pd.read_csv(file_path)

            # Check if required columns exist.
            required_columns = {"Algo", "True-P", "False-P", "False-N"}
            if not required_columns.issubset(df.columns):
                print(
                    f"Skipping {file_name}: Missing one or more required columns.",
                    file=sys.stderr,
                )
                continue

            # Group data by Algo and aggregate TP, FP, FN.
            grouped = df.groupby("Algo").agg(
                {
                    "True-P": "sum",
                    "False-P": "sum",
                    "False-N": "sum",
                }
            )

            # Calculate Precision, Recall, and F1 for each algorithm.
            for algo, row in grouped.iterrows():
                tp = row["True-P"]
                fp = row["False-P"]
                fn = row["False-N"]

                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = (
                    (2 * precision * recall / (precision + recall))
                    if (precision + recall) > 0
                    else 0
                )

                # Use a cleaned-up name for the program under test (PUT)
                put_name = file_name.replace(".csv", "")

                all_metrics.append(
                    {
                        "PUT": put_name,
                        "Algo": algo,
                        "Precision": precision,
                        "Recall": recall,
                        "F1 Score": f1,
                    }
                )
        except Exception as e:
            print(f"Error processing file {file_name}: {e}", file=sys.stderr)

    # Convert the list of metrics into a DataFrame.
    if not all_metrics:
        print("No data processed. Exiting.", file=sys.stderr)
        return

    result_df = pd.DataFrame(all_metrics)

    # Print the final DataFrame to standard output as a CSV table.
    # The float_format argument ensures consistent formatting.
    result_df.to_csv(sys.stdout, index=False, float_format="%.6f")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory_path>", file=sys.stderr)
        sys.exit(1)

    directory_path = sys.argv[1]
    calculate_and_print_csv(directory_path)
