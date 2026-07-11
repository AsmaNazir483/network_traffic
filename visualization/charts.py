import matplotlib.pyplot as plt

def plot_attack_distribution(attack_counts):
    plt.figure(figsize=(8, 5))
    plt.bar(attack_counts.keys(), attack_counts.values(), color="crimson")
    plt.title("Attack Type Distribution")
    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("outputs/attack_distribution.png")
    plt.show()

def plot_detector_comparison(comparison_data):
    names = [d["detector_name"] for d in comparison_data]
    rates = [d["anomaly_rate_percent"] for d in comparison_data]

    plt.figure(figsize=(8, 5))
    plt.bar(names, rates, color="steelblue")
    plt.title("Detector Comparison")
    plt.ylabel("Anomaly Rate (%)")
    plt.tight_layout()
    plt.savefig("outputs/detector_comparison.png")
    plt.show()