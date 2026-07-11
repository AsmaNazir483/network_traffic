from abc import ABC, abstractmethod

class BaseDetector(ABC):
    """Abstract base class — har detector ko ye methods implement karne honge"""

    def __init__(self, name):
        self._name = name
        self._total_checked = 0
        self._total_anomalies = 0

    @abstractmethod
    def detect(self, data):
        pass

    @abstractmethod
    def get_detector_type(self):
        pass

    def get_summary(self):
        return {
            "detector_name": self._name,
            "total_checked": self._total_checked,
            "total_anomalies": self._total_anomalies
        }

    @property
    def name(self):
        return self._name