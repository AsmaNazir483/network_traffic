import numpy as np
from models.base_detector import BaseDetector

class StatisticalAnomalyDetector(BaseDetector):
    """Z-score based statistical detection — NumPy use karta hai"""

    def __init__(self, threshold=3):
        super().__init__(name="Statistical Detector (Z-Score)")
        self.threshold = threshold

    def detect(self, data):
        data = np.array(data)
        mean = np.mean(data)
        std = np.std(data)

        if std == 0:
            z_scores = np.zeros(len(data))
        else:
            z_scores = np.abs((data - mean) / std)

        anomalies = z_scores > self.threshold

        self._total_checked = len(data)
        self._total_anomalies = int(np.sum(anomalies))

        return anomalies

    def get_detector_type(self):
        return "Statistical"