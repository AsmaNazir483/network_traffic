CREATE DATABASE network_traffic_db;
USE network_traffic_db;


-- Attack categories table
CREATE TABLE attack_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(30) UNIQUE NOT NULL,
    severity_level VARCHAR(10) DEFAULT 'Low'
);

-- Connections table (main data)
CREATE TABLE connections (
    connection_id INT AUTO_INCREMENT PRIMARY KEY,
    duration INT,
    protocol_type VARCHAR(10),
    service VARCHAR(20),
    flag VARCHAR(10),
    src_bytes BIGINT,
    dst_bytes BIGINT,
    category_id INT,
    is_anomaly BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES attack_categories(category_id)
);

-- Alerts table
CREATE TABLE alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    connection_id INT,
    alert_message VARCHAR(255),
    detected_by VARCHAR(50),
    alert_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (connection_id) REFERENCES connections(connection_id)
);
DELIMITER //

CREATE TRIGGER after_anomaly_insert
AFTER INSERT ON connections
FOR EACH ROW
BEGIN
    IF NEW.is_anomaly = TRUE THEN
        INSERT INTO alerts (connection_id, alert_message, detected_by)
        VALUES (NEW.connection_id, 'Suspicious traffic auto-detected via trigger', 'DB Trigger');
    END IF;
END;
//

DELIMITER ;