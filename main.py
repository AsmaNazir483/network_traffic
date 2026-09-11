from dotenv import load_dotenv
import os
import numpy as np


from database.db_connection import DatabaseConnection
from repository.connection_repository import ConnectionRepository
from repository.alert_repository import AlertRepository
from models.connection_record import ConnectionRecord
from models.rule_based_detector import RuleBasedDetector
from utils.data_loader import load_csv_data, clean_data
from visualization.charts import plot_attack_distribution, plot_detector_comparison
from sklearn.ensemble import IsolationForest

load_dotenv()

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]


def detect_anomalies(df, features, threshold=2.0):
    """
    Multiple features ka combined anomaly score nikalta hai.
    Jitna zyada features 'unusual' honge, utna zyada score hoga.
    """
    total_score = np.zeros(len(df))
    for feature in features:
        mean = df[feature].mean()
        std = df[feature].std()
        if std > 0:
            z_score = np.abs((df[feature] - mean) / std)
            total_score += z_score
    return total_score > threshold


def main():
    # ---------------- Step 1: Data Load & Clean ----------------
    df = load_csv_data("data/KDDTrain+.txt", columns)
    df = clean_data(df)
    df_sample = df.head(500).copy()
    print(f"Loaded {len(df_sample)} records")

    df_sample['actual_is_attack'] = df_sample['label'] != 'normal'

    # ---------------- Step 2: Database Connect ----------------
    db = DatabaseConnection(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
    db.connect()

    conn_repo = ConnectionRepository(db)

    # ---------------- Step 3: Convert Rows to ConnectionRecord Objects ----------------
    records = []
    for _, row in df_sample.iterrows():
        record = ConnectionRecord(
            duration=row["duration"], protocol_type=row["protocol_type"],
            service=row["service"], flag=row["flag"],
            src_bytes=row["src_bytes"], dst_bytes=row["dst_bytes"],
            label=row["label"]
        )
        records.append(record)

    # ---------------- Step 4: Statistical Detector (Meaningful Features) ----------------
    # 'count' aur 'serror_rate' DoS/Probe attacks ke liye achhe indicators hote hain
    features_used = ['count', 'srv_count', 'serror_rate', 'dst_host_serror_rate']
    stat_predictions = detect_anomalies(df_sample, features_used, threshold=2.0)

    correct_stat = (stat_predictions == df_sample['actual_is_attack'].values).sum()
    stat_accuracy = correct_stat / len(df_sample) * 100
    print(f"Statistical Detector Accuracy: {stat_accuracy:.2f}%")

    # ---------------- Step 5: Rule-Based Detector ----------------
    rule_detector = RuleBasedDetector(byte_threshold=5000, duration_threshold=100)
    rule_results = rule_detector.detect(records)

    correct_rule = (np.array(rule_results) == df_sample['actual_is_attack'].values).sum()
    rule_accuracy = correct_rule / len(df_sample) * 100
    print(f"Rule-Based Detector Accuracy: {rule_accuracy:.2f}%")

    # ---------------- Step 6: Mark Records (Statistical Detector Ke Results Se) ----------------
    for i, is_anomaly in enumerate(stat_predictions):
        if is_anomaly:
            records[i].mark_as_anomaly()


        # ---------------- ML-Based Detector (Isolation Forest) ----------------
    ml_features = df_sample[['count', 'srv_count', 'serror_rate', 
                               'dst_host_serror_rate', 'src_bytes', 'dst_bytes', 'duration']]
    
    iso_forest = IsolationForest(contamination=0.47, random_state=42)
    ml_predictions = iso_forest.fit_predict(ml_features) == -1   # -1 means anomaly in sklearn

    correct_ml = (ml_predictions == df_sample['actual_is_attack'].values).sum()
    ml_accuracy = correct_ml / len(df_sample) * 100
    print(f"ML (Isolation Forest) Accuracy: {ml_accuracy:.2f}%")

    # ---------------- Step 7: Save to Database ----------------
    for record in records:
        conn_repo.insert_connection(record)
    print(f"{len(records)} records saved to database.")

    # ---------------- Step 8: Visualization ----------------
    attack_summary = df_sample["label"].value_counts().to_dict()
    plot_attack_distribution(attack_summary)

    comparison = [
          {"detector_name": "Statistical Detector", "total_checked": len(df_sample),
         "total_anomalies": int(np.sum(stat_predictions)), "anomaly_rate_percent": round(stat_accuracy, 2)},
        {"detector_name": "Rule-Based Detector", "total_checked": len(df_sample),
         "total_anomalies": sum(rule_results), "anomaly_rate_percent": round(rule_accuracy, 2)},
        {"detector_name": "ML (Isolation Forest)", "total_checked": len(df_sample),
         "total_anomalies": int(np.sum(ml_predictions)), "anomaly_rate_percent": round(ml_accuracy, 2)},
    ]
    plot_detector_comparison(comparison)
    

    db.close()


if __name__ == "__main__":
    main()