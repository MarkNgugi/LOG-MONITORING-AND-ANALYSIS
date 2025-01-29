#!/bin/bash

# Path to the Redis log file
REDIS_LOG_FILE="/var/log/redis/redis-server.log"

# API endpoint for Redis logs
API_ENDPOINT="http://127.0.0.1:8000/api/redis/logs/"

# User ID and Log Source Name
USER_ID="1"
LOG_SOURCE_NAME="REDIS TEST"

# Function to process Redis logs
process_redis_logs() {
    while IFS= read -r line; do
        # Skip empty lines
        if [[ -z "$line" ]]; then
            continue
        fi

        # Extract the timestamp correctly (Include Day)
        # Example log: "1422:M 26 Jan 2025 00:37:33.568 # User requested shutdown..."
        timestamp=$(echo "$line" | awk '{print $2, $3, $4, $5}')
        message=$(echo "$line" | cut -d' ' -f7-)

        # Skip lines that don't match the expected format
        if [[ -z "$timestamp" || -z "$message" ]]; then
            continue
        fi

        # Debug: Show original timestamp
        echo "Original Timestamp: $timestamp"

        # Convert Redis timestamp to ISO 8601 format (YYYY-MM-DDThh:mm:ss)
        # Step 1: Remove milliseconds (if they exist)
        timestamp_without_ms=$(echo "$timestamp" | sed 's/\.[0-9]\{3\}//')

        # Step 2: Convert to ISO 8601 format
        iso_timestamp=$(date -d "$timestamp_without_ms" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null)

        # If conversion fails, skip this log entry
        if [[ -z "$iso_timestamp" ]]; then
            echo "Error: Invalid timestamp format '$timestamp'"
            continue
        fi

        # Debug: Show converted timestamp
        echo "Converted Timestamp: $iso_timestamp"

        # Escape special characters in the message
        escaped_message=$(echo "$message" | sed 's/"/\\"/g')

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "REDIS",
    "timestamp": "$iso_timestamp",
    "message": "$escaped_message",
    "log_source_name": "$LOG_SOURCE_NAME",
    "user_id": "$USER_ID"
}
EOF
)

        # Debug: Show JSON payload
        echo "JSON Payload: $json_payload"

        # Send to API
        curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT"
    done < "$REDIS_LOG_FILE"
}

# Main execution
echo "Processing Redis logs..."
process_redis_logs

echo "Done."
