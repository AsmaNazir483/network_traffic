class AlertRepository:
    """Alerts table ke liye CRUD"""

    def __init__(self, db_connection):
        self.db = db_connection

    def insert_alert(self, alert):
        query = "INSERT INTO alerts (connection_id, alert_message, detected_by) VALUES (%s, %s, %s)"
        cursor = self.db.get_connection().cursor()
        cursor.execute(query, (alert.connection_id, alert.message, alert.detected_by))
        self.db.get_connection().commit()
        cursor.close()

    def get_all_alerts(self):
        cursor = self.db.get_connection().cursor(dictionary=True)
        cursor.execute("SELECT * FROM alerts ORDER BY alert_time DESC")
        result = cursor.fetchall()
        cursor.close()
        return result