import mysql.connector
from mysql.connector import Error


class DatabaseConnection:
    """MySQL se connect karne wali class"""

    def __init__(self, host, user, password, database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database
        self.connection = None

    def connect(self):
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )

            if self.connection.is_connected():
                print("✅ Database connected successfully!")

        except Error as e:
            print(f"❌ Database connection failed: {e}")
            self.connection = None

    def get_connection(self):
        return self.connection

    def close(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("Database connection closed.")