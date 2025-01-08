import logging
import mysql.connector
from mysql.connector import Error
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN
import numpy as np
import pandas as pd
import psutil
from sklearn.base import BaseEstimator, ClusterMixin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Database configuration
db_config = {
    "host": "localhost",
    "user": "sigma",
    "password": "sigma",
    "database": "sigma_db",
}

class IncrementalDBSCAN(BaseEstimator, ClusterMixin):
    def __init__(self, eps=0.5, min_samples=5):
        self.eps = eps
        self.min_samples = min_samples
        self.core_samples_indices_ = []
        self.labels_ = np.array([])
        self.n_clusters_ = 0

    def fit(self, X):
        db = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        db.fit(X)
        self.labels_ = db.labels_
        self.core_samples_indices_ = db.core_sample_indices_
        self.n_clusters_ = len(set(self.labels_)) - (1 if -1 in self.labels_ else 0)
        return self

    def partial_fit(self, X):
        if len(self.labels_) == 0:
            return self.fit(X)
        else:
            db = DBSCAN(eps=self.eps, min_samples=self.min_samples)
            db.fit(X)
            new_labels = db.labels_
            new_core_samples_indices = db.core_sample_indices_

            # Update labels
            self.labels_ = np.concatenate([self.labels_, new_labels])
            self.core_samples_indices_ = np.concatenate([self.core_samples_indices_, new_core_samples_indices])
            self.n_clusters_ = len(set(self.labels_)) - (1 if -1 in self.labels_ else 0)
            return self

def fetch_data(offset, batch_size):
    """Fetch data from the sigma_alerts table in batches."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            select_query = """
            SELECT id, title, tags, computer_name, user_id, event_id, provider_name, target_user_name, system_time
            FROM sigma_alerts
            LIMIT %s OFFSET %s
            """
            cursor.execute(select_query, (batch_size, offset))
            data = cursor.fetchall()
        logging.info(f"Fetched {len(data)} records from database with query: {select_query % (batch_size, offset)}")
        return data
    except Error as e:
        logging.error(f"Error fetching data: {e}")
        return []
    finally:
        if connection.is_connected():
            connection.close()

def ensure_column_exists():
    """Ensure the dbscan_cluster and event_category columns exist in the sigma_alerts table."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            cursor.execute("SHOW COLUMNS FROM sigma_alerts LIKE 'dbscan_cluster'")
            result = cursor.fetchone()
            if not result:
                cursor.execute("ALTER TABLE sigma_alerts ADD COLUMN dbscan_cluster INT")
                connection.commit()
                logging.info("Added 'dbscan_cluster' column to 'sigma_alerts' table.")
            cursor.execute("SHOW COLUMNS FROM sigma_alerts LIKE 'event_category'")
            result = cursor.fetchone()
            if not result:
                cursor.execute("ALTER TABLE sigma_alerts ADD COLUMN event_category VARCHAR(255)")
                connection.commit()
                logging.info("Added 'event_category' column to 'sigma_alerts' table.")
    except Error as e:
        logging.error(f"Error ensuring 'dbscan_cluster' and 'event_category' columns exist: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def categorize_events(data_df):
    """Categorize events based on predefined rules."""
    conditions = [
        (data_df['user_id'].notnull() & data_df['computer_name'].notnull() & data_df['title'].notnull()),
        (data_df['target_user_name'].notnull() & data_df['computer_name'].notnull() & data_df['title'].notnull()),
        (data_df['user_id'].isnull() & data_df['target_user_name'].isnull() & data_df['computer_name'].notnull()),
        (data_df['title'].notnull() & data_df['tags'].notnull())
    ]
    choices = [
        'User Originated Threats',
        'Targeted User Threats',
        'System Level Threats',
        'Mitre Tactics & Techniques Pattern Deviation'
    ]
    data_df['event_category'] = np.select(conditions, choices, default='unknown')
    return data_df

def preprocess_data(data, focus_columns):
    """Preprocess the data for DBSCAN based on focus columns."""
    data_df = pd.DataFrame(data, columns=[
        'id', 'title', 'tags', 'computer_name', 'user_id', 'event_id', 'provider_name', 'target_user_name', 'system_time'
    ])
    data_df = categorize_events(data_df)

    # Encode categorical variables
    encoded_columns = []
    for column in focus_columns:
        le = LabelEncoder()
        data_df[f"{column}_encoded"] = le.fit_transform(data_df[column].fillna("unknown"))
        encoded_columns.append(f"{column}_encoded")

    X = data_df[encoded_columns]

    # Normalize the feature matrix
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, data_df

def run_incremental_dbscan(data, incremental_dbscan):
    """Run Incremental DBSCAN clustering on the provided data and return the cluster labels."""
    incremental_dbscan.partial_fit(data)
    return incremental_dbscan.labels_

def update_cluster_labels(data_df, cluster_labels):
    """Update the sigma_alerts table with the cluster labels."""
    try:
        connection = mysql.connector.connect(**db_config)
        with connection.cursor() as cursor:
            update_query = """
            UPDATE sigma_alerts
            SET dbscan_cluster = %s, event_category = %s
            WHERE id = %s
            """
            update_data = [
                (int(cluster_labels[i]), data_df.loc[i, 'event_category'], int(data_df.loc[i, 'id']))
                for i in range(len(data_df))
            ]
            cursor.executemany(update_query, update_data)
            connection.commit()
            logging.info(f"Updated {len(update_data)} records with cluster labels and event categories.")
    except Error as e:
        logging.error(f"Error updating cluster labels: {e}")
    finally:
        if connection.is_connected():
            connection.close()

def determine_batch_size():
    """Determine the appropriate batch size based on system memory and sample data."""
    mem = psutil.virtual_memory()
    available_memory = mem.available / (1024 ** 2)  # Convert to MB
    logging.info(f"Available memory: {available_memory:.2f} MB")

    # Estimate an average size for each data row by sampling a small batch
    sample_batch_size = 1000
    sample_data = fetch_data(0, sample_batch_size)
    if not sample_data:
        return 10000  # Default batch size if no data is fetched

    sample_df = pd.DataFrame(sample_data)
    sample_memory_usage = sample_df.memory_usage(deep=True).sum() / (1024 ** 2)  # Convert to MB
    average_row_size_mb = sample_memory_usage / sample_batch_size
    logging.info(f"Estimated average row size: {average_row_size_mb:.6f} MB")

    # Calculate the batch size based on estimated row size and available memory
    usage_limit_mb = available_memory * 0.1  # Use a very conservative 10% of available memory
    batch_size = int(usage_limit_mb / average_row_size_mb)
    # Adjust batch size based on the dimensionality of the data
    if sample_df.shape[1] < 10:
        batch_size = min(batch_size, 10000)  # Low-dimensional data
    else:
        batch_size = min(batch_size, 2000)  # High-dimensional data
    logging.info(f"Determined batch size: {batch_size}")

    return batch_size

def process_goal(goal, focus_columns, data, incremental_dbscan):
    """Process a single goal."""
    logging.info(f"Processing goal: {goal}")
    preprocessed_data, data_df = preprocess_data(data, focus_columns)
    cluster_labels = run_incremental_dbscan(preprocessed_data, incremental_dbscan)
    update_cluster_labels(data_df, cluster_labels)

    # Calculate and log the number of outliers (label -1 in DBSCAN)
    num_outliers = np.sum(cluster_labels == -1)
    logging.info(f"Number of outliers detected for goal '{goal}': {num_outliers}")

def detect_anomalies():
    """Fetch data, run Incremental DBSCAN, and update the database with cluster labels."""
    ensure_column_exists()

    batch_size = determine_batch_size()
    offset = 0

    # Initialize Incremental DBSCAN instances for each goal
    incremental_dbscans = {goal: IncrementalDBSCAN(eps=0.5, min_samples=5) for goal in goals.keys()}

    while True:
        data = fetch_data(offset, batch_size)
        if not data:
            logging.warning("No more data found in the database.")
            break

        # Log memory usage before processing
        mem_before = psutil.virtual_memory().used / (1024 ** 2)
        logging.info(f"Memory used before processing batch: {mem_before:.2f} MB")

        # Process each goal in parallel
        with ThreadPoolExecutor(max_workers=len(goals)) as executor:
            futures = [
                executor.submit(process_goal, goal, focus_columns, data, incremental_dbscans[goal])
                for goal, focus_columns in goals.items()
            ]
            for future in as_completed(futures):
                future.result()

        # Log memory usage after processing
        mem_after = psutil.virtual_memory().used / (1024 ** 2)
        logging.info(f"Memory used after processing batch: {mem_after:.2f} MB")

        # Move to the next batch
        offset += batch_size

# Updated goals and their focus columns
goals = {
    "User Originated Threats": ["user_id", "computer_name", "title", "tags"],
    "Targeted User Threats": ["target_user_name", "computer_name", "title", "tags"],
    "System Level Threats": ["computer_name", "title", "tags", "system_time"],
    "Mitre Tactics & Techniques Pattern Deviation": ["title", "tags", "system_time"]
}

# Run the script immediately with existing data
detect_anomalies()
