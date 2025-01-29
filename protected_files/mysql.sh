#!/bin/bash

# Path to the MySQL error log file
MYSQL_ERROR_LOG_FILE="/var/log/mysql/error.log"

# API endpoint for MySQL logs
API_ENDPOINT="http://127.0.0.1:8000/api/mysql/logs/"

# User ID and Log Source Name
USER_ID="1"
LOG_SOURCE_NAME="MARK TEST"

# Function to process MySQL error logs
process_mysql_error_logs() {
    while IFS= read -r line; do
        # Skip empty lines
        if [[ -z "$line" ]]; then
            continue
        fi

        # Extract the timestamp and message
        timestamp=$(echo "$line" | awk '{print $1}')
        error_message=$(echo "$line" | cut -d' ' -f2-)

        # Debug: Show parsed data
        echo "Parsed MySQL Error Log: $timestamp, $error_message"

        # Escape special characters in the error message
        escaped_error_message=$(echo "$error_message" | sed 's/"/\\"/g')

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "error",
    "timestamp": "$timestamp",
    "error_message": "$escaped_error_message",
    "log_source_name": "$LOG_SOURCE_NAME",
    "user_id": "$USER_ID"
}
EOF
)

        # Debug: Show JSON payload
        echo "JSON Payload: $json_payload"

        # Send to API
        curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT"
    done < "$MYSQL_ERROR_LOG_FILE"
}

# Main execution
echo "Processing MySQL error logs..."
process_mysql_error_logs

echo "Done."