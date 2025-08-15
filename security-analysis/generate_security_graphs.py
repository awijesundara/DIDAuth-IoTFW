#!/usr/bin/env python3
import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

parser = argparse.ArgumentParser(description="Generate security detection graphs from CSV log")
parser.add_argument("csv_file", nargs="?", default="security_log.csv", help="Path to CSV log file")
args = parser.parse_args()

csv_file = args.csv_file
output_dir = "security_graphs"
os.makedirs(output_dir, exist_ok=True)

if not os.path.exists(csv_file):
    raise SystemExit(f"CSV file {csv_file} not found")

df = pd.read_csv(csv_file)
if "iteration" in df.columns:
    df["iteration"] = pd.to_numeric(df["iteration"], errors="coerce")

df["latency"] = pd.to_numeric(df.get("latency"), errors="coerce")

df["success_flag"] = df["result"].eq("success").astype(int)

overall = df.groupby("scenario")["success_flag"].mean().reset_index()
plt.figure(figsize=(8, 5))
sns.barplot(data=overall, x="scenario", y="success_flag")
plt.ylabel("Detection Rate")
plt.ylim(0, 1)
plt.title("Overall Detection Rates")
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "overall_detection_rate.png"))
plt.close()

if "iteration" in df.columns:
    iter_df = df.groupby(["iteration", "scenario"])["success_flag"].mean().reset_index()
    plt.figure(figsize=(8, 5))
    sns.lineplot(data=iter_df, x="iteration", y="success_flag", hue="scenario", marker="o")
    plt.ylabel("Detection Rate")
    plt.ylim(0, 1)
    plt.title("Detection Rate per Iteration")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "detection_rate_iterations.png"))
    plt.close()

lat_mean = df.groupby("scenario")["latency"].mean().reset_index()
plt.figure(figsize=(8,5))
sns.barplot(data=lat_mean, x="scenario", y="latency")
plt.ylabel("Mean Latency (s)")
plt.title("Average Latency by Scenario")
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "mean_latency.png"))
plt.close()

plt.figure(figsize=(8,5))
sns.boxplot(data=df, x="scenario", y="latency")
plt.ylabel("Latency (s)")
plt.title("Latency Distribution by Scenario")
plt.tight_layout()
plt.savefig(os.path.join(output_dir, "latency_boxplot.png"))
plt.close()
