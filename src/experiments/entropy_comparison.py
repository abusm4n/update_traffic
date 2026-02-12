#!/usr/bin/env python3
"""
Experiment 1: Cross-Device Entropy Comparison Study

Analyzes entropy metrics across different IoT devices to identify
security and randomness differences in update traffic.
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from scipy import stats

# Configuration
ENTROPY_DIR = os.path.expanduser("~/update_traffic/controlled/entropy")
OUTPUT_DIR = os.path.expanduser("~/update_traffic/analysis_output")
FIGURES_DIR = os.path.join(OUTPUT_DIR, "figures")
DATA_DIR = os.path.join(OUTPUT_DIR, "data")

# Create output directories
Path(FIGURES_DIR).mkdir(parents=True, exist_ok=True)
Path(DATA_DIR).mkdir(parents=True, exist_ok=True)

# Device names to process
DEVICES = ['dlink', 'eufy', 'sony_tv', 'tapo', 'xiaomi']
METRICS = ['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']

def load_entropy_data(device_name):
    """Load entropy CSV for a device (use formatted version if available)"""
    formatted_path = os.path.join(ENTROPY_DIR, f"{device_name}_formatted.csv")
    raw_path = os.path.join(ENTROPY_DIR, f"{device_name}.csv")
    
    # Prefer formatted data
    if os.path.exists(formatted_path):
        try:
            df = pd.read_csv(formatted_path)
            # Parse tuple strings like "(1, 0.82769)" 
            for metric in METRICS:
                if metric in df.columns:
                    df[metric] = df[metric].apply(lambda x: extract_entropy_value(x))
            return df, "formatted"
        except Exception as e:
            print(f"Error reading formatted {device_name}: {e}")
    
    # Fall back to raw data
    if os.path.exists(raw_path):
        try:
            df = pd.read_csv(raw_path)
            # Filter for valid entropy rows
            df = df[['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']].copy()
            # Remove negative values (invalid entropies)
            for metric in METRICS:
                df[metric] = pd.to_numeric(df[metric], errors='coerce')
                df[metric] = df[metric].mask(df[metric] < 0, np.nan)
            return df, "raw"
        except Exception as e:
            print(f"Error reading raw {device_name}: {e}")
    
    return None, None

def extract_entropy_value(x):
    """Extract entropy value from tuple string like '(1, 0.82769)'"""
    try:
        if isinstance(x, str):
            # Remove parentheses and split
            x = x.strip('()')
            parts = x.split(',')
            if len(parts) >= 2:
                return float(parts[1].strip())
        return np.nan
    except:
        return np.nan

def compute_statistics(df, device_name):
    """Compute comprehensive statistics for a device"""
    stats_dict = {'device': device_name}
    
    for metric in METRICS:
        if metric in df.columns:
            col = df[metric]
            col = pd.to_numeric(col, errors='coerce')
            col = col[col >= 0]  # Remove invalid values
            
            short_name = metric.split('_')[1]  # 'shannon', 'renyi', 'tsallis'
            stats_dict[f'{short_name}_mean'] = col.mean()
            stats_dict[f'{short_name}_std'] = col.std()
            stats_dict[f'{short_name}_min'] = col.min()
            stats_dict[f'{short_name}_max'] = col.max()
            stats_dict[f'{short_name}_median'] = col.median()
            stats_dict[f'{short_name}_q25'] = col.quantile(0.25)
            stats_dict[f'{short_name}_q75'] = col.quantile(0.75)
            stats_dict[f'{short_name}_count'] = col.count()
    
    return stats_dict

def main():
    print("=" * 70)
    print("Cross-Device Entropy Comparison Study")
    print("=" * 70)
    
    # Step 1: Load and process data
    print("\n[1] Loading entropy data for all devices...")
    device_data = {}
    all_entropy = []
    
    for device in DEVICES:
        df, source = load_entropy_data(device)
        if df is not None:
            device_data[device] = df
            print(f"  ✓ {device:12} - {len(df):5} packets from {source} source")
            
            # Prepare for combined analysis
            df['device'] = device
            all_entropy.append(df)
        else:
            print(f"  ✗ {device:12} - Not found")
    
    # Combine all data
    combined_df = pd.concat(all_entropy, ignore_index=True)
    
    # Step 2: Compute statistics per device
    print("\n[2] Computing entropy statistics per device...")
    stats_list = []
    for device in DEVICES:
        if device in device_data:
            stats = compute_statistics(device_data[device], device)
            stats_list.append(stats)
    
    stats_df = pd.DataFrame(stats_list)
    stats_df.to_csv(os.path.join(DATA_DIR, "entropy_statistics.csv"), index=False)
    print(f"  ✓ Statistics saved to entropy_statistics.csv")
    print("\nSummary Statistics (means):")
    print(stats_df[['device', 'shannon_mean', 'renyi_mean', 'tsallis_mean']].to_string(index=False))
    
    # Step 3: Statistical testing
    print("\n[3] Performing statistical tests...")
    
    # ANOVA: Are entropy means significantly different across devices?
    shannon_groups = [device_data[d]['entropy_shannon'].dropna().values for d in DEVICES if d in device_data]
    f_stat, p_value = stats.f_oneway(*shannon_groups)
    print(f"\n  Shannon Entropy ANOVA:")
    print(f"    F-statistic: {f_stat:.4f}")
    print(f"    P-value: {p_value:.2e}")
    print(f"    Significant difference: {'YES' if p_value < 0.05 else 'NO'}")
    
    # Step 4: Create visualizations
    print("\n[4] Creating visualizations...")
    
    # Figure 1: Box plots
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    
    for idx, metric in enumerate(['entropy_shannon', 'entropy_renyi', 'entropy_tsallis']):
        name = metric.split('_')[1].capitalize()
        
        # Prepare data
        plot_data = []
        labels = []
        for device in DEVICES:
            if device in device_data:
                vals = device_data[device][metric].dropna()
                vals = vals[vals >= 0]
                plot_data.append(vals)
                labels.append(device.capitalize())
        
        # Box plot
        bp = axes[idx].boxplot(plot_data, labels=labels, patch_artist=True)
        for patch in bp['boxes']:
            patch.set_facecolor('lightblue')
        axes[idx].set_ylabel('Entropy Value', fontsize=11)
        axes[idx].set_title(f'{name} Entropy Distribution', fontsize=12, fontweight='bold')
        axes[idx].grid(True, alpha=0.3, axis='y')
        axes[idx].tick_params(axis='x', rotation=45)
    
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_boxplots.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_boxplots.pdf")
    plt.close()
    
    # Figure 2: Distribution histograms
    fig, axes = plt.subplots(3, 5, figsize=(16, 10))
    
    for metric_idx, metric in enumerate(METRICS):
        name = metric.split('_')[1].capitalize()
        for device_idx, device in enumerate(DEVICES):
            ax = axes[metric_idx, device_idx]
            if device in device_data:
                vals = device_data[device][metric].dropna()
                vals = vals[vals >= 0]
                ax.hist(vals, bins=30, color='steelblue', edgecolor='black', alpha=0.7)
                ax.set_title(f'{device.upper()}\n{name}', fontsize=10)
                ax.set_xlabel('Entropy', fontsize=9)
                if device_idx == 0:
                    ax.set_ylabel('Frequency', fontsize=9)
                ax.grid(True, alpha=0.3, axis='y')
    
    plt.suptitle('Entropy Distributions Across Devices', fontsize=14, fontweight='bold', y=0.995)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_distributions.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_distributions.pdf")
    plt.close()
    
    # Figure 3: Heatmap of mean entropy values
    heatmap_data = stats_df[['device', 'shannon_mean', 'renyi_mean', 'tsallis_mean']].set_index('device')
    heatmap_data.columns = ['Shannon', 'Rényi', 'Tsallis']
    
    plt.figure(figsize=(8, 5))
    sns.heatmap(heatmap_data.T, annot=True, fmt='.3f', cmap='RdYlGn', 
                cbar_kws={'label': 'Entropy Value'}, linewidths=1, linecolor='gray')
    plt.title('Mean Entropy Values by Device', fontsize=12, fontweight='bold')
    plt.xlabel('Device', fontsize=11)
    plt.ylabel('Entropy Metric', fontsize=11)
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_heatmap.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_heatmap.pdf")
    plt.close()
    
    # Figure 4: Violin plots for comparison
    fig, ax = plt.subplots(figsize=(12, 6))
    
    violin_data = []
    for device in DEVICES:
        if device in device_data:
            vals = device_data[device]['entropy_shannon'].dropna()
            vals = vals[vals >= 0]
            for v in vals[:min(100, len(vals))]:  # Limit for clarity
                violin_data.append({'Device': device.capitalize(), 'Shannon Entropy': v})
    
    violin_df = pd.DataFrame(violin_data)
    sns.violinplot(data=violin_df, x='Device', y='Shannon Entropy', ax=ax)
    ax.set_ylabel('Shannon Entropy', fontsize=11)
    ax.set_xlabel('Device', fontsize=11)
    ax.set_title('Shannon Entropy Distribution (Violin Plot)', fontsize=12, fontweight='bold')
    ax.grid(True, alpha=0.3, axis='y')
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES_DIR, "entropy_violins.pdf"), dpi=300, bbox_inches='tight')
    print("  ✓ Saved: entropy_violins.pdf")
    plt.close()
    
    # Step 5: Summary report
    print("\n[5] Generating summary report...")
    
    with open(os.path.join(DATA_DIR, "entropy_analysis_report.txt"), "w") as f:
        f.write("=" * 70 + "\n")
        f.write("CROSS-DEVICE ENTROPY ANALYSIS REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total devices analyzed: {len(DEVICES)}\n")
        f.write(f"Total packets processed: {len(combined_df):,}\n")
        f.write(f"Entropy metrics: Shannon, Rényi, Tsallis\n\n")
        
        f.write("STATISTICAL FINDINGS\n")
        f.write("-" * 70 + "\n")
        f.write(f"Shannon Entropy ANOVA F-statistic: {f_stat:.4f}\n")
        f.write(f"Shannon Entropy ANOVA P-value: {p_value:.2e}\n")
        f.write(f"Significant device differences: {'YES (p < 0.05)' if p_value < 0.05 else 'NO (p >= 0.05)'}\n\n")
        
        f.write("DEVICE RANKINGS (by Shannon Entropy Mean)\n")
        f.write("-" * 70 + "\n")
        ranked = stats_df[['device', 'shannon_mean', 'shannon_std']].sort_values('shannon_mean', ascending=False)
        for idx, row in ranked.iterrows():
            f.write(f"  {idx+1}. {row['device']:12} - Mean: {row['shannon_mean']:.4f} ± {row['shannon_std']:.4f}\n")
        f.write("\n")
        
        f.write("INTERPRETATION\n")
        f.write("-" * 70 + "\n")
        f.write("Higher entropy values indicate more randomness/encryption in traffic.\n")
        f.write("Lower entropy may indicate structured patterns, plaintext, or compression.\n\n")
        
        f.write("OUTPUTS GENERATED\n")
        f.write("-" * 70 + "\n")
        f.write("Data files:\n")
        f.write("  - entropy_statistics.csv\n")
        f.write("Figures:\n")
        f.write("  - entropy_boxplots.pdf\n")
        f.write("  - entropy_distributions.pdf\n")
        f.write("  - entropy_heatmap.pdf\n")
        f.write("  - entropy_violins.pdf\n")
    
    print("  ✓ Report saved to entropy_analysis_report.txt")
    
    print("\n" + "=" * 70)
    print("✓ Analysis Complete!")
    print("=" * 70)
    print(f"\nOutputs saved to:")
    print(f"  Data: {DATA_DIR}/")
    print(f"  Figures: {FIGURES_DIR}/")

if __name__ == "__main__":
    main()
