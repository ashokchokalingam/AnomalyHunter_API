from flask import Flask, jsonify, request
from flask_cors import CORS
import mysql.connector.pooling
from mysql.connector import Error
from flask_caching import Cache

app = Flask(__name__)

# Enable CORS for specific origins
CORS(app, resources={r"/api/*": {"origins": "http://172.16.0.75:8080"}})

# Database configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sigma",
    "database": "sigma_db",
}

# Create a connection pool
db_pool = mysql.connector.pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=10,
    **db_config
)

def get_db_connection():
    """Get a connection from the pool."""
    try:
        connection = db_pool.get_connection()
        return connection
    except Error as e:
        app.logger.error(f"Error getting connection from pool: {e}")
        return None

def fetch_data(query, params=None):
    """Fetch data from the database using the provided query and parameters."""
    connection = get_db_connection()
    if not connection:
        return {"error": "Database connection failed"}, 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        data = cursor.fetchall()
        return data, 200
    except Error as e:
        app.logger.error(f"Error fetching data: {e}")
        return {"error": f"Error fetching data: {e}"}, 500
    finally:
        if connection:
            connection.close()

def normalize_case(data, fields):
    """Normalize the case and remove extra spaces for specified fields in the data."""
    for item in data:
        for field in fields:
            if field in item and isinstance(item[field], str):
                # Remove extra spaces and convert to lowercase
                item[field] = item[field].replace(' ', '').lower()
    return data

# Configure caching
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# Alerts endpoint
@app.route('/api/alerts', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_alerts():
    """Fetch paginated records from the sigma_alerts table."""
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=100, type=int)

    # Validate pagination parameters
    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT id, title, tags, description, system_time, computer_name, user_id, event_id, provider_name, dbscan_cluster, raw, ip_address, ruleid, rule_level, task, target_user_name, target_domain_name
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    ORDER BY system_time DESC
    LIMIT %s OFFSET %s
    """
    alerts, status_code = fetch_data(query, (per_page, offset))

    if status_code != 200:
        return jsonify(alerts), status_code

    total_query = "SELECT COUNT(*) as total FROM sigma_alerts WHERE system_time >= NOW() - INTERVAL 7 DAY"
    total_records, status_code = fetch_data(total_query)

    if status_code != 200:
        return jsonify(total_records), status_code

    # Normalize fields
    alerts = normalize_case(alerts, ['title', 'tags', 'description', 'computer_name', 'user_id', 'event_id', 'provider_name', 'dbscan_cluster', 'raw', 'ip_address', 'ruleid', 'rule_level', 'task', 'target_user_name', 'target_domain_name'])

    response = {
        "alerts": alerts,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200

# Total count endpoint
@app.route('/api/total_count', methods=['GET'])
@cache.cached(timeout=60)
def get_total_count():
    """Fetch total count of events from the sigma_alerts table for the last 7 days."""
    query = """
    SELECT COUNT(*) AS total_count
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    """
    total_count, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(total_count), status_code

    response = {
        "total_count": total_count[0]["total_count"]
    }
    return jsonify(response), 200

# Tags endpoint
@app.route('/api/tags', methods=['GET'])
@cache.cached(timeout=60)
def get_tags():
    """Fetch tags and their counts from the sigma_alerts table for the last 7 days."""
    query = """
    SELECT tags, COUNT(*) AS total_count
    FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    GROUP BY tags
    """
    tags, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(tags), status_code

    tags = normalize_case(tags, ['tags'])

    response = {
        "tags": tags,
    }
    return jsonify(response), 200

# User origin endpoint
@app.route('/api/user_origin', methods=['GET'])
@cache.cached(timeout=300)
def get_user_origin():
    """Fetch user origin logs from the sigma_alerts table for the last 7 days, limited to top 50 users by unique titles."""
    query = """
    SELECT
        user_id AS user_origin,
        COUNT(DISTINCT title) AS unique_titles
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND user_id IS NOT NULL
    GROUP BY
        user_id
    ORDER BY
        unique_titles DESC
    LIMIT 50
    """
    user_origin_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_origin_logs), status_code

    user_origin_logs = normalize_case(user_origin_logs, ['user_origin'])

    response = {
        "user_origin_logs": user_origin_logs,
    }
    return jsonify(response), status_code

# User impacted endpoint
@app.route('/api/user_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_user_impacted():
    """Fetch user impacted logs from the sigma_alerts table for the last 7 days, limited to top 50 users by unique titles."""
    query = """
    SELECT
        target_user_name AS user_impacted,
        COUNT(DISTINCT title) AS unique_titles
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND target_user_name IS NOT NULL
    GROUP BY
        target_user_name
    ORDER BY
        unique_titles DESC
    LIMIT 50
    """
    user_impacted_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(user_impacted_logs), status_code

    user_impacted_logs = normalize_case(user_impacted_logs, ['user_impacted'])

    response = {
        "user_impacted_logs": user_impacted_logs,
    }
    return jsonify(response), status_code

# Computer impacted endpoint
@app.route('/api/computer_impacted', methods=['GET'])
@cache.cached(timeout=300)
def get_computer_impacted():
    """Fetch computer impacted logs from the sigma_alerts table for the last 7 days, limited to top 50 computers by unique titles."""
    query = """
    SELECT
        computer_name,
        COUNT(DISTINCT title) AS unique_titles
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND computer_name IS NOT NULL
    GROUP BY
        computer_name
    ORDER BY
        unique_titles DESC
    LIMIT 50
    """
    computer_impacted_logs, status_code = fetch_data(query)

    if status_code != 200:
        return jsonify(computer_impacted_logs), status_code

    computer_impacted_logs = normalize_case(computer_impacted_logs, ['computer_name'])

    response = {
        "computer_impacted_logs": computer_impacted_logs,
    }
    return jsonify(response), status_code

# User origin timeline endpoint
@app.route('/api/user_origin_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_origin_timeline():
    """Fetch user origin timeline logs for the last 7 days."""
    user_origin = request.args.get('user_origin')
    if not user_origin:
        return jsonify({"error": "user_origin parameter is required"}), 400

    query = """
    SELECT
        user_id AS user_origin,
        title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND user_id = %s
    GROUP BY
        user_id, title, tags, description, rule_level
    ORDER BY
        title;
    """
    user_origin_timeline, status_code = fetch_data(query, (user_origin,))

    if status_code != 200:
        return jsonify(user_origin_timeline), status_code

    user_origin_timeline = normalize_case(user_origin_timeline, ['user_origin', 'title', 'tags', 'description'])

    response = {
        "user_origin_timeline": user_origin_timeline,
    }
    return jsonify(response), status_code

# User impacted timeline endpoint
@app.route('/api/user_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_timeline():
    """Fetch user impacted timeline logs for the last 7 days."""
    user_impacted = request.args.get('user_impacted')
    if not user_impacted:
        return jsonify({"error": "user_impacted parameter is required"}), 400

    query = """
    SELECT
        target_user_name AS user_impacted,
        title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND target_user_name = %s
    GROUP BY
        target_user_name, title, tags, description, rule_level
    ORDER BY
        title;
    """
    user_impacted_timeline, status_code = fetch_data(query, (user_impacted,))

    if status_code != 200:
        return jsonify(user_impacted_timeline), status_code

    user_impacted_timeline = normalize_case(user_impacted_timeline, ['user_impacted', 'title', 'tags', 'description'])

    response = {
        "user_impacted_timeline": user_impacted_timeline,
    }
    return jsonify(response), status_code

# Computer impacted timeline endpoint
@app.route('/api/computer_impacted_timeline', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_computer_impacted_timeline():
    """Fetch computer impacted timeline logs for the last 7 days."""
    computer_name = request.args.get('computer_name')
    if not computer_name:
        return jsonify({"error": "computer_name parameter is required"}), 400

    query = """
    SELECT
        computer_name, title, tags, description, rule_level, MIN(system_time) AS first_time_seen, MAX(system_time) AS last_time_seen, COUNT(*) AS total_events
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND computer_name = %s
    GROUP BY
        computer_name, title, tags, description, rule_level
    ORDER BY
        title;
    """
    computer_impacted_timeline, status_code = fetch_data(query, (computer_name,))

    if status_code != 200:
        return jsonify(computer_impacted_timeline), status_code

    computer_impacted_timeline = normalize_case(computer_impacted_timeline, ['computer_name', 'title', 'tags', 'description'])

    response = {
        "computer_impacted_timeline": computer_impacted_timeline,
    }
    return jsonify(response), status_code

# User impacted logs endpoint
@app.route('/api/user_impacted_logs', methods=['GET'])
@cache.cached(timeout=300, query_string=True)
def get_user_impacted_logs():
    """Fetch logs for a selected user_impacted and title, including raw column, with pagination."""
    user_impacted = request.args.get('user_impacted')
    title = request.args.get('title')
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=500, type=int)

    if not user_impacted:
        return jsonify({"error": "user_impacted parameter is required"}), 400
    if not title:
        return jsonify({"error": "title parameter is required"}), 400

    # Validate pagination parameters
    if page < 1 or per_page < 1:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    offset = (page - 1) * per_page

    query = """
    SELECT
        id, title, tags, description, system_time, computer_name, user_id, event_id, provider_name, dbscan_cluster, ip_address, ruleid, rule_level, task, target_user_name, target_domain_name, raw
    FROM
        sigma_alerts
    WHERE
        system_time >= NOW() - INTERVAL 7 DAY
        AND target_user_name = %s
        AND title = %s
    ORDER BY
        system_time DESC
    LIMIT %s OFFSET %s;
    """
    user_impacted_logs, status_code = fetch_data(query, (user_impacted, title, per_page, offset))

    if status_code != 200:
        return jsonify(user_impacted_logs), status_code

    total_query = """
    SELECT COUNT(*) as total FROM sigma_alerts
    WHERE system_time >= NOW() - INTERVAL 7 DAY
    AND target_user_name = %s
    AND title = %s
    """
    total_records, status_code = fetch_data(total_query, (user_impacted, title))

    if status_code != 200:
        return jsonify(total_records), status_code

    user_impacted_logs = normalize_case(user_impacted_logs, ['title', 'tags', 'description', 'computer_name', 'user_id', 'event_id', 'provider_name', 'ip_address', 'ruleid', 'rule_level', 'task', 'target_user_name', 'target_domain_name', 'raw'])

    response = {
        "user_impacted_logs": user_impacted_logs,
        "pagination": {
            "current_page": page,
            "per_page": per_page,
            "total_records": total_records[0]["total"],
            "total_pages": (total_records[0]["total"] + per_page - 1) // per_page,
        },
    }
    return jsonify(response), 200

if __name__ == '__main__':
    # Run the app on the specified host and port
    app.run(host='172.16.0.75', port=5000, debug=True)
