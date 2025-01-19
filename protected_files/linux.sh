#!/bin/bash

# Paths to log files
AUTHLOG_FILE="/var/log/authh.log"
SYSLOG_FILE="/var/log/sys"

# API endpoint
API_ENDPOINT="http://127.0.0.1:8000/api/linux/logs/"

# Function to process auth logs
process_authlogs() {
    echo "Processing auth logs..."
    while read -r line; do
        # Extract the timestamp (ISO format)
        timestamp=$(echo "$line" | awk '{print $1}')
        
        # Extract the hostname (field after timestamp)
        hostname=$(echo "$line" | awk '{print $2}')
        
        # Extract the service and optional process ID
        service=$(echo "$line" | awk '{print $3}' | sed 's/\[.*\]:$//')
        process_id=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' || echo "null")
        
        # Extract optional user, command, PWD, session status, and UID
        user=$(echo "$line" | grep -oP 'user \K\w+' || echo "null")
        command=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "null")
        pwd=$(echo "$line" | grep -oP 'CWD=\K.*' || echo "null")
        session_status=$(echo "$line" | grep -oE 'session (opened|closed)' || echo "null")
        uid=$(echo "$line" | grep -oP 'uid=\K[0-9]+' || echo "null")
        
        # Extract the log message (everything after the service and process ID)
        message=$(echo "$line" | sed -E 's/^.*\[?[0-9]*\]:?\s?//')

        # Ensure no field is improperly assigned
        hostname=$(echo "$hostname" | grep -vE '^Executing$' || echo "ubuntu")
        timestamp=$(echo "$timestamp" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}' || echo "null")

        # Debug: Show extracted auth log data
        echo "Authlog: $timestamp, $hostname, $service, $process_id, $user, $command, $pwd, $session_status, $uid, $message"

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "authlog",
    "timestamp": "$timestamp",
    "hostname": "$hostname",
    "service": "$service",
    "process_id": $process_id,
    "user": "$user",
    "command": "$command",
    "pwd": "$pwd",
    "session_status": "$session_status",
    "uid": $uid,
    "message": "$message"
}
EOF
)
        # Send to API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")
        echo "$response"
    done < "$AUTHLOG_FILE"
    echo "Auth logs processing completed."
}

# Function to process syslogs
process_syslogs() {
    echo "Processing syslogs..."
    while read -r line; do
        # Extract the timestamp (up to and including the timezone offset)
        timestamp=$(echo "$line" | grep -oP '^\S+')

        # Extract the hostname (immediately after the timestamp)
        hostname=$(echo "$line" | awk '{print $2}')

        # Extract the service and process ID (from "service[process_id]:")
        service_process=$(echo "$line" | awk '{print $3}' | sed 's/://g')
        service=$(echo "$service_process" | grep -oP '^[^\[]*')
        process_id=$(echo "$service_process" | grep -oP '(?<=\[)[0-9]+(?=\])')

        # Extract the message (everything after the first colon after service and process ID)
        message=$(echo "$line" | sed -E 's/^[^:]+: //')

        # Debug: Display extracted syslog data
        echo "Syslog: $timestamp, $hostname, $service, $process_id, $message"

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "syslog",
    "timestamp": "$timestamp",
    "hostname": "$hostname",
    "service": "$service",
    "process_id": ${process_id:-null},
    "log_level": "N/A",
    "message": "$message"
}
EOF
)
        # Send to API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")
        echo "$response"
    done < "$SYSLOG_FILE"
    echo "Syslogs processing completed."
}

# Main execution
echo "Starting log processing..."
process_authlogs
process_syslogs
echo "All logs processed successfully."
