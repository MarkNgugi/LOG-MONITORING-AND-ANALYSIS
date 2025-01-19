#!/bin/bash

# Paths to the log files
ACCESS_LOG_FILE="/var/log/nginx/access.log.1"
ERROR_LOG_FILE="/var/log/nginx/error.log"

# API endpoint
API_ENDPOINT="http://127.0.0.1:8000/api/nginx/logs/"

# Function to process access logs
process_access_logs() {
    while read -r line; do
        # Parse the access log line and construct a JSON payload
        client_ip=$(echo "$line" | awk '{print $1}')
        timestamp=$(echo "$line" | awk -F'[][]' '{print $2}')
        request_line=$(echo "$line" | awk '{print $7}')
        response_code=$(echo "$line" | awk '{print $9}')
        response_size=$(echo "$line" | awk '{print $10}')
        referrer=$(echo "$line" | awk '{print $11}')
        user_agent=$(echo "$line" | awk -F'"' '{print $6}')
        
        # Escape double quotes in the referrer and user_agent fields to avoid JSON formatting issues
        referrer=$(echo "$referrer" | sed 's/"/\\"/g')
        user_agent=$(echo "$user_agent" | sed 's/"/\\"/g')

        # Check for missing values and assign defaults if necessary
        client_ip=${client_ip:-"N/A"}
        timestamp=${timestamp:-"N/A"}
        request_line=${request_line:-"N/A"}
        response_code=${response_code:-"N/A"}
        response_size=${response_size:-"0"}
        referrer=${referrer:-"N/A"}
        user_agent=${user_agent:-"N/A"}

        # Construct the JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "access",
    "timestamp": "$timestamp",
    "client_ip": "$client_ip",
    "request_line": "$request_line",
    "response_code": "$response_code",
    "response_size": "$response_size",
    "referrer": "$referrer",
    "user_agent": "$user_agent"
}
EOF
)
        # Send the JSON payload to the API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")

        # Output the response
        echo "$json_payload"
        echo "$response"
    done < "$ACCESS_LOG_FILE"
}

# Function to process error logs
process_error_logs() {
    while read -r line; do
        # Parse the error log line and construct a JSON payload
        timestamp=$(echo "$line" | awk '{print $1 " " $2}')
        log_level=$(echo "$line" | awk '{print $3}')
        process_id=$(echo "$line" | awk -F'#' '{print $1}' | awk '{print $NF}')
        error_message=$(echo "$line" | sed -e 's/\"/\\\"/g' -e 's/\\/\//g' -e 's/\n/ /g')
        
        # Extract client IP, if available
        client_ip=$(echo "$line" | grep -oP 'client: \K[0-9.]+')

        # If no client IP is found, set it to a valid placeholder (e.g., "0.0.0.0")
        if [ -z "$client_ip" ]; then
            client_ip="0.0.0.0"
        fi

        # Check for missing values and assign defaults if necessary
        timestamp=${timestamp:-"N/A"}
        log_level=${log_level:-"N/A"}
        process_id=${process_id:-"N/A"}
        error_message=${error_message:-"N/A"}

        # Construct the JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "error",
    "timestamp": "$timestamp",
    "log_level": "$log_level",
    "process_id": "$process_id",
    "error_message": "$error_message",
    "client_ip": "$client_ip"
}
EOF
)
        # Send the JSON payload to the API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")

        # Output the response
        echo "$json_payload"
        echo "$response"
    done < "$ERROR_LOG_FILE"
}



# Main script execution
echo "Processing access logs..."
process_access_logs
echo "Processing error logs..."
process_error_logs
echo "Done."
