import os
import logging
import schedule
import time
from datetime import datetime
import mysql.connector
from mysql.connector import Error
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import psutil  # For monitoring system resources

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "sigma",
    "password": "sigma",
    "database": "sigma_db",
}

def fetch_data():
    """Fetch data from the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            select_query = """
            SELECT id, title, tags, computer_name, user_id, target_user_name, event_id, provider_name
            FROM sigma_alerts
            WHERE title NOT IN ('Failed Logon From Public IP', 'User Logoff Event', 'External Remote SMB Logon from Public IP')
            """
            cursor.execute(select_query)
            data = cursor.fetchall()
        return data
    except Error as e:
        logging.error(f"Error fetching data: {e}")
        return []
    finally:
        if connection.is_connected():
            connection.close()

def ensure_column_exists():
    """Ensure the dbscan_cluster column exists in the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM sigma_alerts LIKE 'dbscan_cluster'")
            result = cursor.fetchone()
            if not result:
                cursor.execute("ALTER TABLE sigma_alerts ADD COLUMN dbscan_cluster INT")
                connection.commit()
                logging.info("Added 'dbscan_cluster' column to 'sigma_alerts' table.")
    except Error as e:
        logging.error(f"Error ensuring 'dbscan_cluster' column exists: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def preprocess_data(data):
    """Preprocess the data for Isolation Forest."""
    def handle_nulls(value):
        return value if value not in (None, " ", "", "N/A", "-") else "unknown"

    titles = [handle_nulls(row[1]) for row in data]
    tags = [handle_nulls(row[2]) for row in data]
    computer_names = [handle_nulls(row[3]) for row in data]
    user_ids = [handle_nulls(row[4]) for row in data]
    target_user_names = [handle_nulls(row[5]) for row in data]
    event_ids = [handle_nulls(row[6]) for row in data]
    provider_names = [handle_nulls(row[7]) for row in data]

    tfidf_vectorizer = TfidfVectorizer(stop_words="english")
    title_tfidf = tfidf_vectorizer.fit_transform(titles)
    tag_tfidf = tfidf_vectorizer.fit_transform(tags)

    label_encoder = LabelEncoder()
    computer_name_encoded = label_encoder.fit_transform(computer_names)
    user_id_encoded = label_encoder.fit_transform(user_ids)
    target_user_name_encoded = label_encoder.fit_transform(target_user_names)
    event_id_encoded = label_encoder.fit_transform(event_ids)
    provider_name_encoded = label_encoder.fit_transform(provider_names)

    combined_data = np.hstack((
        title_tfidf.toarray(),
        tag_tfidf.toarray(),
        computer_name_encoded.reshape(-1, 1),
        user_id_encoded.reshape(-1, 1),
        target_user_name_encoded.reshape(-1, 1),
        event_id_encoded.reshape(-1, 1),
        provider_name_encoded.reshape(-1, 1)
    ))

    return combined_data

def run_isolation_forest(data):
    """Run Isolation Forest on the provided data and return the anomaly scores."""
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)

    isolation_forest = IsolationForest(contamination=0.1, random_state=42)  # Set contamination to 0.1
    isolation_forest.fit(data_scaled)
    anomaly_scores = isolation_forest.decision_function(data_scaled)
    anomaly_labels = isolation_forest.predict(data_scaled)

    # Convert anomaly labels to -1 for anomalies and 0 for normal
    anomaly_labels = np.where(anomaly_labels == -1, -1, 0)

    return anomaly_labels

def update_cluster_labels(data, anomaly_labels):
    """Update the sigma_alerts table with the anomaly labels."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            update_query = """
            UPDATE sigma_alerts
            SET dbscan_cluster = %s
            WHERE id = %s
            """
            update_data = [(int(anomaly_labels[i]), data[i][0]) for i in range(len(data))]
            cursor.executemany(update_query, update_data)
            connection.commit()
            logging.info(f"Updated {len(update_data)} records with anomaly labels.")
    except Error as e:
        logging.error(f"Error updating anomaly labels: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def detect_anomalies():
    """Fetch data, run Isolation Forest, and update the database with anomaly labels."""
    ensure_column_exists()

    data = fetch_data()
    if not data:
        logging.warning("No data found in the database.")
        return

    preprocessed_data = preprocess_data(data)
    start_time = datetime.now()

    # Split data into batches to avoid memory issues
    batch_size = determine_batch_size(len(preprocessed_data))
    anomaly_labels = np.array([])

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = []
        for i in range(0, len(preprocessed_data), batch_size):
            batch_data = preprocessed_data[i:i + batch_size]
            futures.append(executor.submit(run_isolation_forest, batch_data))

        for future in as_completed(futures):
            batch_labels = future.result()
            anomaly_labels = np.concatenate((anomaly_labels, batch_labels))

    end_time = datetime.now()
    duration = end_time - start_time
    logging.info(f"Isolation Forest anomaly detection completed in {duration.total_seconds()} seconds.")

    update_cluster_labels(data, anomaly_labels)

def determine_batch_size(total_samples):
    """Determine the appropriate batch size based on system memory and total samples."""
    mem = psutil.virtual_memory()
    available_memory = mem.available / (1024 ** 2)  # Convert to MB
    logging.info(f"Available memory: {available_memory} MB")

    # Estimate batch size based on available memory (this is a heuristic)
    batch_size = min(max(1000, int(available_memory / 10)), total_samples)
    logging.info(f"Determined batch size: {batch_size}")
    return batch_size

# Run the script immediately with existing data
detect_anomalies()

# Schedule anomaly detection every 5 minutes
schedule.every(5).minutes.do(detect_anomalies)

while True:
    schedule.run_pending()
    time.sleep(1)
