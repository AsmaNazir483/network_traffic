from models.base_detector import BaseDetector

class RuleBasedDetector(BaseDetector):
    """Fixed threshold rules ke through detection"""

    def __init__(self, byte_threshold=5000, duration_threshold=100):
        super().__init__(name="Rule-Based Detector")
        self.byte_threshold = byte_threshold
        self.duration_threshold = duration_threshold

    def detect(self, connection_records):
        anomalies = []
        for record in connection_records:
            is_suspicious = (
                record.src_bytes > self.byte_threshold or
                record.duration > self.duration_threshold
            )
            anomalies.append(is_suspicious)

        self._total_checked = len(connection_records)
        self._total_anomalies = sum(anomalies)
        return anomalies

    def get_detector_type(self):
        return "Rule-Based"