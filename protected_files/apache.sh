#!/bin/bash

# Paths to the log files
ACCESS_LOG_FILE="/var/log/apache2/access.log.1"
ERROR_LOG_FILE="/var/log/apache2/error.log"

# API endpoint
API_ENDPOINT="http://127.0.0.1:8000/api/apache/logs/"

# Function to process access logs
process_access_logs() {
    while read -r line; do
        # Parse the access log line and construct a JSON payload
        client_ip=$(echo "$line" | awk '{print $1}')
        timestamp=$(echo "$line" | awk '{print $4}' | sed 's/\[//')
        request_line=$(echo "$line" | awk -F\" '{print $2}')
        response_code=$(echo "$line" | awk '{print $9}')
        response_size=$(echo "$line" | awk '{print $10}')
        referrer=$(echo "$line" | awk -F\" '{print $4}')
        user_agent=$(echo "$line" | awk -F\" '{print $6}')
        
        # Fix for missing fields
        remote_logname="N/A"
        remote_user="N/A"

        # Debug: Show parsed data
        echo "Parsed Access Log: $client_ip, $timestamp, $request_line, $response_code, $response_size, $referrer, $user_agent"

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "access",
    "client_ip": "$client_ip",
    "timestamp": "$timestamp",
    "request_line": "$request_line",
    "response_code": $response_code,
    "response_size": $response_size,
    "referrer": "$referrer",
    "user_agent": "$user_agent",
    "remote_logname": "$remote_logname",
    "remote_user": "$remote_user"
}
EOF
)
        # Send to API
        curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT"
    done < "$ACCESS_LOG_FILE"
}

# Function to process error logs
process_error_logs() {
    while read -r line; do
        # Extract fields
        timestamp=$(echo "$line" | awk -F'[][]' '{print $2}')
        module=$(echo "$line" | awk -F'[][]' '{print $4}' | awk -F: '{print $1}')
        log_level=$(echo "$line" | awk -F'[][]' '{print $4}' | awk -F: '{print $2}')
        client_ip=$(echo "$line" | grep -oP '(?<=\[client )[^:]*')
        process_id=$(echo "$line" | grep -oP '(?<=\[pid )\d+' || echo "N/A")
        error_message=$(echo "$line" | sed -E 's/.*\] \[[^]]*\] //')

        # Provide default value for missing client_ip
        if [[ -z "$client_ip" ]]; then
            client_ip="0.0.0.0"  # Use a valid IP placeholder
        fi

        # Debugging output
        echo "Parsed Error Log: $timestamp, $module, $log_level, $client_ip, $process_id, $error_message"

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "error",
    "timestamp": "$timestamp",
    "module": "$module",
    "log_level": "$log_level",
    "error_message": "$error_message",
    "client_ip": "$client_ip",
    "remote_logname": "N/A",
    "remote_user": "N/A",
    "process_id": $process_id
}
EOF
)
        # Send to API
        curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT"
    done < "$ERROR_LOG_FILE"
}

# Main execution
echo "Processing access logs..."
process_access_logs

echo "Processing error logs..."
process_error_logs

echo "Done."