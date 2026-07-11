from dotenv import load_dotenv
import os

from database.db_connection import DatabaseConnection
from repository.connection_repository import ConnectionRepository
from repository.alert_repository import AlertRepository
from models.connection_record import ConnectionRecord
from models.statistical_detector import StatisticalAnomalyDetector
from models.rule_based_detector import RuleBasedDetector
from utils.data_loader import load_csv_data, clean_data
from visualization.charts import plot_attack_distribution, plot_detector_comparison

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

def main():
    # Step 1: Load & clean data
    df = load_csv_data("data/KDDTrain+.txt", columns)
    df = clean_data(df)
    df_sample = df.head(500)   # test ke liye chhota sample
    print(f"Loaded {len(df_sample)} records")

    # Step 2: Database connect
    db = DatabaseConnection(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
    db.connect()

    conn_repo = ConnectionRepository(db)
    alert_repo = AlertRepository(db)

    # Step 3: Convert rows to ConnectionRecord objects
    records = []
    for _, row in df_sample.iterrows():
        record = ConnectionRecord(
            duration=row["duration"], protocol_type=row["protocol_type"],
            service=row["service"], flag=row["flag"],
            src_bytes=row["src_bytes"], dst_bytes=row["dst_bytes"],
            label=row["label"]
        )
        records.append(record)

    # Step 4: Run detectors
    stat_detector = StatisticalAnomalyDetector(threshold=3)
    rule_detector = RuleBasedDetector(byte_threshold=5000, duration_threshold=100)

    src_bytes_data = df_sample["src_bytes"].values
    stat_results = stat_detector.detect(src_bytes_data)
    rule_results = rule_detector.detect(records)

    for i, is_anomaly in enumerate(stat_results):
        if is_anomaly:
            records[i].mark_as_anomaly()

    # Step 5: Save to database
    for record in records:
        conn_repo.insert_connection(record)

    # Step 6: Analysis + Visualization
    attack_summary = df_sample["label"].value_counts().to_dict()
    plot_attack_distribution(attack_summary)

    comparison = [stat_detector.get_summary(), rule_detector.get_summary()]
    for c in comparison:
        c["anomaly_rate_percent"] = round((c["total_anomalies"] / c["total_checked"]) * 100, 2)
    plot_detector_comparison(comparison)

    db.close()

if __name__ == "__main__":
    main()