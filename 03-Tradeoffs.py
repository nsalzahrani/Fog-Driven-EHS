#!/usr/bin/env python3
"""
Performance Trade‑Off Analysis for Fog‑Driven e‑Healthcare Authentication

This script reproduces the trade‑off analysis from Section 7.5 of the manuscript:
    - Average latency, energy, response rate, throughput for each method type
    - Energy vs. Latency
    - Response Rate vs. Number of Tasks
    - Energy Consumption vs. Number of Tasks
    - Latency vs. Number of Users
    - Energy Consumption vs. Response Rate
    - Throughput vs. Latency

Data is taken from Table 12 (average metrics) and the comparative figures.
The results are plotted using matplotlib.
"""

import numpy as np
import matplotlib.pyplot as plt

# ------------------------------
# Data from Table 12 (Average performance metrics by method type)
# ------------------------------
method_types = ["Lattice-Based", "Pairing-Based", "Identity-Based", "ECC-Based", "Hash-Based (Proposed)"]

# Average Latency (ms) – from Table 12
avg_latency = [57.20, 45.00, 56.50, 66.00, 24.80]

# Average Energy Consumption (mJ) – from Table 12
avg_energy = [581.70, 199.00, 218.00, 195.00, 155.00]

# Average Response Rate (Sec) – from Table 12 (response time per task)
avg_response_rate = [0.45, 0.31, 0.52, 0.35, 0.17]

# Average Throughput (tasks per second) – from Table 12
avg_throughput = [11.33, 8.08, 12.66, 4.87, 7.16]

# Additional data for trade‑off curves (from Figure 11 & 12)
# These are synthetic but follow the trends described in the manuscript.
# In a real implementation, you would replace these with measured values.
number_of_tasks = np.array([10, 50, 100, 200, 500, 1000])
number_of_users = np.array([100, 500, 1000, 5000, 10000])

# Response Rate (seconds) as function of number of tasks for each method
# Based on Figure 11 (Response Rate vs. No. of Tasks)
response_rate_vs_tasks = {
    "Lattice-Based": 0.45 * (1 + number_of_tasks / 2000),
    "Pairing-Based": 0.31 * (1 + number_of_tasks / 1500),
    "Identity-Based": 0.52 * (1 + number_of_tasks / 1800),
    "ECC-Based": 0.35 * (1 + number_of_tasks / 1200),
    "Hash-Based (Proposed)": 0.17 * (1 + number_of_tasks / 4000)
}

# Energy Consumption (mJ) as function of number of tasks
energy_vs_tasks = {
    "Lattice-Based": 581.70 * (1 + number_of_tasks / 500),
    "Pairing-Based": 199.00 * (1 + number_of_tasks / 800),
    "Identity-Based": 218.00 * (1 + number_of_tasks / 700),
    "ECC-Based": 195.00 * (1 + number_of_tasks / 600),
    "Hash-Based (Proposed)": 155.00 * (1 + number_of_tasks / 1200)
}

# Latency (ms) as function of number of users
latency_vs_users = {
    "Lattice-Based": 57.20 * (1 + number_of_users / 3000),
    "Pairing-Based": 45.00 * (1 + number_of_users / 4000),
    "Identity-Based": 56.50 * (1 + number_of_users / 3500),
    "ECC-Based": 66.00 * (1 + number_of_users / 2500),
    "Hash-Based (Proposed)": 24.80 * (1 + number_of_users / 8000)
}

# Throughput vs. Latency (relationship from Figure 12 bottom‑right)
# For each method, we generate a curve: as throughput increases, latency changes.
# We'll use a simple model: latency = base_latency + (throughput - base_throughput)*slope
throughput_range = np.linspace(2, 20, 50)
latency_vs_throughput = {}
for method, base_lat, base_thr in zip(method_types, avg_latency, avg_throughput):
    # slope determined such that latency increases moderately with throughput
    slope = base_lat / (base_thr * 5)  # arbitrary but plausible
    latency_vs_throughput[method] = base_lat + slope * (throughput_range - base_thr)
    # ensure no negative latency
    latency_vs_throughput[method] = np.maximum(latency_vs_throughput[method], base_lat * 0.8)

# ------------------------------
# Plotting Functions
# ------------------------------
plt.style.use('seaborn-v0_8-whitegrid')
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']
markers = ['o', 's', '^', 'D', 'v']

def plot_energy_vs_latency():
    """Figure 12 top‑left: Energy vs. Latency"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.scatter(avg_latency[i], avg_energy[i], label=method, 
                    s=150, c=colors[i], marker=markers[i], edgecolors='black')
    plt.xlabel("Average Latency (ms)", fontsize=12)
    plt.ylabel("Average Energy Consumption (mJ)", fontsize=12)
    plt.title("Energy vs. Latency Trade‑Off", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("energy_vs_latency.png", dpi=150)
    plt.show()

def plot_response_rate_vs_tasks():
    """Figure 11 top: Response Rate vs. Number of Tasks"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.plot(number_of_tasks, response_rate_vs_tasks[method], 
                 label=method, color=colors[i], marker=markers[i], markevery=0.2)
    plt.xlabel("Number of Tasks", fontsize=12)
    plt.ylabel("Response Rate (seconds)", fontsize=12)
    plt.title("Response Rate vs. Number of Tasks", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("response_rate_vs_tasks.png", dpi=150)
    plt.show()

def plot_energy_vs_tasks():
    """Figure 11 middle: Energy Consumption vs. Number of Tasks"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.plot(number_of_tasks, energy_vs_tasks[method], 
                 label=method, color=colors[i], marker=markers[i], markevery=0.2)
    plt.xlabel("Number of Tasks", fontsize=12)
    plt.ylabel("Energy Consumption (mJ)", fontsize=12)
    plt.title("Energy Consumption vs. Number of Tasks", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("energy_vs_tasks.png", dpi=150)
    plt.show()

def plot_latency_vs_users():
    """Figure 11 bottom: Latency vs. Number of Users"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.plot(number_of_users, latency_vs_users[method], 
                 label=method, color=colors[i], marker=markers[i], markevery=0.2)
    plt.xlabel("Number of Users", fontsize=12)
    plt.ylabel("Latency (ms)", fontsize=12)
    plt.title("Latency vs. Number of Users", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("latency_vs_users.png", dpi=150)
    plt.show()

def plot_energy_vs_response_rate():
    """Figure 12 top‑right: Energy Consumption vs. Response Rate"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.scatter(avg_response_rate[i], avg_energy[i], label=method, 
                    s=150, c=colors[i], marker=markers[i], edgecolors='black')
    plt.xlabel("Response Rate (seconds)", fontsize=12)
    plt.ylabel("Energy Consumption (mJ)", fontsize=12)
    plt.title("Energy vs. Response Rate", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("energy_vs_response_rate.png", dpi=150)
    plt.show()

def plot_throughput_vs_latency():
    """Figure 12 bottom‑right: Throughput vs. Latency"""
    plt.figure(figsize=(8, 5))
    for i, method in enumerate(method_types):
        plt.plot(throughput_range, latency_vs_throughput[method], 
                 label=method, color=colors[i], linewidth=2)
        # mark the average point
        plt.scatter(avg_throughput[i], avg_latency[i], s=100, c=colors[i], 
                    marker=markers[i], edgecolors='black', zorder=5)
    plt.xlabel("Throughput (tasks/second)", fontsize=12)
    plt.ylabel("Latency (ms)", fontsize=12)
    plt.title("Throughput vs. Latency", fontsize=14)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig("throughput_vs_latency.png", dpi=150)
    plt.show()

def compute_improvements():
    """Calculate percentage improvements of Hash‑Based over other methods."""
    print("\n=== Performance Improvements of Hash‑Based (Proposed) over Other Methods ===")
    hash_idx = method_types.index("Hash-Based (Proposed)")
    for i, method in enumerate(method_types):
        if i == hash_idx:
            continue
        lat_imp = (avg_latency[i] - avg_latency[hash_idx]) / avg_latency[i] * 100
        en_imp = (avg_energy[i] - avg_energy[hash_idx]) / avg_energy[i] * 100
        resp_imp = (avg_response_rate[i] - avg_response_rate[hash_idx]) / avg_response_rate[i] * 100
        thr_imp = (avg_throughput[hash_idx] - avg_throughput[i]) / avg_throughput[i] * 100 if avg_throughput[i] > 0 else 0
        print(f"\n{method}:")
        print(f"  Latency improvement   : {lat_imp:.1f}% (lower is better)")
        print(f"  Energy improvement    : {en_imp:.1f}% (lower is better)")
        print(f"  Response rate reduction: {resp_imp:.1f}% (lower response time is better)")
        print(f"  Throughput improvement: {thr_imp:.1f}% (higher is better)")

# ------------------------------
# Main Execution
# ------------------------------
if __name__ == "__main__":
    print("Generating trade‑off analysis plots as per manuscript Section 7.5...")
    plot_energy_vs_latency()
    plot_response_rate_vs_tasks()
    plot_energy_vs_tasks()
    plot_latency_vs_users()
    plot_energy_vs_response_rate()
    plot_throughput_vs_latency()
    compute_improvements()
    print("\nAll plots saved as PNG files in the current directory.")