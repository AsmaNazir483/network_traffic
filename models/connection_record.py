class ConnectionRecord:
    """Encapsulation demonstrate karta hai — private attributes + property getters"""

    def __init__(self, duration, protocol_type, service, flag, src_bytes, dst_bytes, label):
        self.__duration = duration
        self.__protocol_type = protocol_type
        self.__service = service
        self.__flag = flag
        self.__src_bytes = src_bytes
        self.__dst_bytes = dst_bytes
        self.__label = label
        self.__is_anomaly = False

    @property
    def duration(self):
        return self.__duration

    @property
    def src_bytes(self):
        return self.__src_bytes

    @property
    def protocol_type(self):
        return self.__protocol_type

    @property
    def label(self):
        return self.__label

    @property
    def is_anomaly(self):
        return self.__is_anomaly

    def mark_as_anomaly(self):
        self.__is_anomaly = True

    def __str__(self):
        status = "ANOMALY" if self.__is_anomaly else "Normal"
        return f"[{self.__protocol_type}] Bytes: {self.__src_bytes}, Status: {status}"

    def to_dict(self):
        return {
            "duration": self.__duration,
            "protocol_type": self.__protocol_type,
            "service": self.__service,
            "flag": self.__flag,
            "src_bytes": self.__src_bytes,
            "dst_bytes": self.__dst_bytes,
            "label": self.__label,
            "is_anomaly": self.__is_anomaly
        }