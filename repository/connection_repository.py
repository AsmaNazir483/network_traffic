class ConnectionRepository:
    """Poora CRUD (Create, Read, Update, Delete) handle karta hai connections table ke liye"""

    def __init__(self, db_connection):
        self.db = db_connection

    def insert_connection(self, record):
        query = """
            INSERT INTO connections (duration, protocol_type, service, flag, src_bytes, dst_bytes, is_anomaly)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        data = record.to_dict()
        values = (data["duration"], data["protocol_type"], data["service"],
                  data["flag"], data["src_bytes"], data["dst_bytes"], data["is_anomaly"])

        cursor = self.db.get_connection().cursor()
        cursor.execute(query, values)
        self.db.get_connection().commit()
        last_id = cursor.lastrowid
        cursor.close()
        return last_id

    def get_all_connections(self):
        cursor = self.db.get_connection().cursor(dictionary=True)
        cursor.execute("SELECT * FROM connections")
        result = cursor.fetchall()
        cursor.close()
        return result

    def get_anomalies(self):
        cursor = self.db.get_connection().cursor(dictionary=True)
        cursor.execute("SELECT * FROM connections WHERE is_anomaly = TRUE")
        result = cursor.fetchall()
        cursor.close()
        return result

    def update_anomaly_status(self, connection_id, status):
        query = "UPDATE connections SET is_anomaly = %s WHERE connection_id = %s"
        cursor = self.db.get_connection().cursor()
        cursor.execute(query, (status, connection_id))
        self.db.get_connection().commit()
        cursor.close()

    def delete_connection(self, connection_id):
        query = "DELETE FROM connections WHERE connection_id = %s"
        cursor = self.db.get_connection().cursor()
        cursor.execute(query, (connection_id,))
        self.db.get_connection().commit()
        cursor.close()

    def count_by_protocol(self):
        cursor = self.db.get_connection().cursor(dictionary=True)
        cursor.execute("SELECT protocol_type, COUNT(*) as total FROM connections GROUP BY protocol_type")
        result = cursor.fetchall()
        cursor.close()
        return result