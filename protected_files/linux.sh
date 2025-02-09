#!/bin/bash

# Paths to log files
AUTHLOG_FILE="/var/log/auth.log"
SYSLOG_FILE="/var/log/syslog"

# API endpoint
API_ENDPOINT="http://127.0.0.1:8000/api/linux/logs/"

# User ID
USER_ID="1"

# Log Source Name
LOG_SOURCE_NAME="LINUX TEST"

# Specific services to monitor
SERVICES=("apache2" "nginx" "ssh" "mysql" "postgresql")

# Patterns for syslog (strictly matching defined services)
# Patterns for syslog (strictly matching defined services and system events)
SYSLOG_PATTERNS=(
    # SSH-related events
    "sshd.*Failed password"                          # Failed SSH login attempts
    "sshd.*Accepted publickey"                       # SSH logins using keys
    "sshd.*Accepted password"                        # SSH logins using passwords
    "sshd.*session opened"                           # SSH session opened
    "sshd.*session closed"                           # SSH session closed
    "sshd.*Received disconnect"                      # SSH disconnections
    "sshd.*Connection closed"                        # SSH connection closed
    "systemd.*sshd.service:.*(start|stop|restart)"   # SSH service start/stop/restart

    # System-related events
    "systemd.*reboot"                                # System reboots
    "systemd.*shutdown"                              # System shutdowns
    "systemd.*Started Session"                       # User session started
    "systemd.*Stopped Session"                       # User session stopped
    "systemd.*Started .*service"                     # Service start
    "systemd.*Stopped .*service"                     # Service stop
    "systemd.*Failed .*service"                      # Service failure
    "cron.*FAILED"                                   # Cron job failures
    "kernel:.*disk space"                            # Disk space warnings

    # Sudoers and privilege escalation
    "sudo: .*COMMAND=.*"                             # Sudo command execution
    "sudo: .*authentication failure"                 # Failed sudo attempts
    "sudo: .*session opened"                         # Sudo session opened
    "sudo: .*session closed"                         # Sudo session closed
    "sudo: .*user .*NOT in sudoers"                  # Unauthorized sudo attempt
    "sudo: .*user .*password attempt"                # Sudo password attempts

    # User account changes
    "useradd.*new user"                              # New user account creation
    "userdel.*delete user"                           # User account deletion
    "usermod.*modify user"                           # User account modification
    "groupadd.*new group"                            # New group creation
    "groupdel.*delete group"                         # Group deletion
    "groupmod.*modify group"                         # Group modification


    "systemd.*reboot"                                # System reboots
    "systemd.*shutdown"                              # System shutdowns
    "System is rebooting"                            # Explicit system reboot message
    "System is powering down"                        # Explicit system shutdown message

    "CRON\\[[0-9]+\\]: \\([^)]+\\) CMD \\(.*\\)"     # General cron job execution                     
    "CRON.*STARTUP.*fork ok"        # Cron service startup events
    "CRON.*session opened"          # Cron job session start    
    "CRON\[.*\]: \(.*\) CMD \(.*\)"  # Captures cron jobs executed by ANY user (dynamic user detection)
    "CRON.*FAILED"                  # Cron job failures 

    # Kernel panic detection patterns
    "kernel: .*Kernel panic - not syncing"        # General kernel panic event
    "kernel: .*Oops: [0-9]+ \[#.*\]"              # Kernel oops message indicating critical failure

    "kernel:.*No space left on device"           # Kernel disk space warnings
    "kernel:.*EXT4-fs warning.*"                 # EXT4 filesystem space warnings
    "kernel:.*EXT4-fs error.*"                   # EXT4 filesystem errors
    "systemd.*No space left on device"           # Systemd service failure due to no space
    "CRON.*FAILED.*No space left on device"      # Cron job failure due to low disk space
    ".*No space left on device.*"                # General application failures
    ".*Disk usage.*(9[0-9]|100)%"                # High disk usage warnings (90%+)

    "sudo: .*COMMAND=/usr/bin/(cat|less|more) .*sudoers"      # Reading sudoers file
    "sudo: .*COMMAND=/usr/bin/(vim|vi|nano|subl|gedit|code) .*sudoers"  # Editing sudoers file
    "sudo: .*COMMAND=/usr/sbin/visudo"                        # Editing sudoers via visudo

    "sudo: .*Account locked due to too many failed login attempts for .*"  # Sudo lockout
    "faillock.*User .* has been locked due to .* failed login attempts"  # PAM FailLock lockout

    "sudo: .*COMMAND=/usr/sbin/service .* (start|stop|restart).*"  # New pattern
    "sudo: .*COMMAND=/bin/systemctl .* (start|stop|restart).*"     # New pattern
    "sudo: .*COMMAND=/etc/init.d/.* (start|stop|restart).*"  


)

# Patterns for authlog (authentication events & service-related changes)
AUTHLOG_PATTERNS=(
    # SSH-related events
    "sshd.*Failed password"                          # Failed SSH login attempts
    "sshd.*Accepted publickey"                       # SSH logins using keys
    "sshd.*Failed publickey"                         # Failed SSH logins keys
    "sshd.*Accepted password"                        # SSH logins using passwords
    "sshd.*session opened"                           # SSH session opened
    "sshd.*session closed"                           # SSH session closed
    "sshd.*Received disconnect"                      # SSH disconnections
    "sshd.*Connection closed"                        # SSH connection closed

    # Authentication failures
    "authentication failure"                         # General authentication failures
    "failed login"                                   # Failed login attempts
    "user .* logged in"                              # User login events
    "user .* NOT in sudoers"                         # Unauthorized sudo attempts
    "sudo: .*authentication failure"                 # Failed sudo attempts
    "pam_unix\(sudo:auth\): authentication failure"  # Sudo authentication failure (added)
    "sudo: .*incorrect password attempts"            # Incorrect password attempts (added)

    # User account changes
    "useradd.*new user"                              # New user account creation
    "userdel.*delete user"                           # User account deletion
    "usermod.*modify user"                           # User account modification
    "groupadd.*new group"                            # New group creation
    "groupdel.*delete group"                         # Group deletion
    "groupmod.*modify group"                         # Group modification

    # Sudoers file changes
    "sudoers file changed"                           # Changes to sudoers file
    "sudoers: .*syntax error"                        # Sudoers file syntax errors

    # User and group management (added patterns)
    "accounts-daemon: request by system-bus-name.*create user"  # User creation via accounts-daemon
    "groupadd.*new group"                            # New group creation
    "groupadd.*group added to /etc/group"            # Group added to /etc/group
    "groupadd.*group added to /etc/gshadow"          # Group added to /etc/gshadow
    "useradd.*new user"                              # New user creation
    "chfn.*changed user .* information"              # User information changes
    "gpasswd.*members of group .* set by"            # Group membership changes
    "accounts-daemon: request by system-bus-name.*set password and hint of user"  # Password changes

    "System is rebooting"                            # System reboot detected in auth logs
    "System is powering down"                        # System shutdown detected in auth logs

    # Kernel panic detection patterns
    "kernel: .*Kernel panic - not syncing"        # General kernel panic event
    "kernel: .*Oops: [0-9]+ \[#.*\]"              # Kernel oops message indicating critical failure

    "kernel:.*No space left on device"           # Kernel disk space warnings
    "kernel:.*EXT4-fs warning.*"                 # EXT4 filesystem space warnings
    "kernel:.*EXT4-fs error.*"                   # EXT4 filesystem errors
    "systemd.*No space left on device"           # Systemd service failure due to no space
    "CRON.*FAILED.*No space left on device"      # Cron job failure due to low disk space
    ".*No space left on device.*"                # General application failures
    ".*Disk usage.*(9[0-9]|100)%"                # High disk usage warnings (90%+)

    "sudo: .*COMMAND=/usr/bin/(cat|less|more) .*sudoers"      # Reading sudoers file
    "sudo: .*COMMAND=/usr/bin/(vim|vi|nano|subl|gedit|code) .*sudoers"  # Editing sudoers file
    "sudo: .*COMMAND=/usr/sbin/visudo"                        # Editing sudoers via visudo

    "sudo: .*Account locked due to too many failed login attempts for .*"  # Sudo lockout
    "faillock.*User .* has been locked due to .* failed login attempts"  # PAM FailLock lockout


    "sudo: .*COMMAND=/usr/sbin/service .* (start|stop|restart).*"  # New pattern
    "sudo: .*COMMAND=/bin/systemctl .* (start|stop|restart).*"     # New pattern
    "sudo: .*COMMAND=/etc/init.d/.* (start|stop|restart).*"  


)


# Convert patterns into regex strings
SYSLOG_REGEX=$(IFS="|"; echo "${SYSLOG_PATTERNS[*]}")
AUTHLOG_REGEX=$(IFS="|"; echo "${AUTHLOG_PATTERNS[*]}")

# Function to process authentication logs in real-time
process_authlogs_realtime() {
    echo "Listening for new authentication logs..."
    tail -n 0 -f "$AUTHLOG_FILE" | grep --line-buffered -E "$AUTHLOG_REGEX" | while read -r line; do
        # Extract details
        timestamp=$(echo "$line" | awk '{print $1}')
        hostname=$(echo "$line" | awk '{print $2}')
        service=$(echo "$line" | awk '{print $3}' | sed 's/\[.*\]:$//')
        process_id=$(echo "$line" | grep -oP '\[\K[0-9]+(?=\])' || echo "null")
        user=$(echo "$line" | grep -oP 'user \K\w+' || echo "null")
        command=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "null")
        pwd=$(echo "$line" | grep -oP 'CWD=\K.*' || echo "null")
        session_status=$(echo "$line" | grep -oE 'session (opened|closed)' || echo "null")
        uid=$(echo "$line" | grep -oP 'uid=\K[0-9]+' || echo "null")
        message=$(echo "$line" | sed -E 's/^.*\[?[0-9]*\]:?\s?//')

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
    "message": "$message",
    "log_source_name": "$LOG_SOURCE_NAME", 
    "user_id": "$USER_ID"
}
EOF
)

        # Send to API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")
        echo "$response"
    done
}

# Function to process system logs in real-time
process_syslogs_realtime() {
    echo "Listening for new system logs..."
    tail -n 0 -f "$SYSLOG_FILE" | grep --line-buffered -E "$SYSLOG_REGEX" | grep -E "($(IFS="|"; echo "${SERVICES[*]}"))" | while read -r line; do
        # Extract details
        timestamp=$(echo "$line" | grep -oP '^\S+')
        hostname=$(echo "$line" | awk '{print $2}')
        service_process=$(echo "$line" | awk '{print $3}' | sed 's/://g')
        service=$(echo "$service_process" | grep -oP '^[^\[]*')
        process_id=$(echo "$service_process" | grep -oP '(?<=\[)[0-9]+(?=\])')
        message=$(echo "$line" | sed -E 's/^[^:]+: //')

        # Ensure only specified services are logged
        if [[ ! " ${SERVICES[*]} " =~ " $service " ]]; then
            continue
        fi

        # Create JSON payload
        json_payload=$(cat <<EOF
{
    "log_type": "syslog",
    "timestamp": "$timestamp",
    "hostname": "$hostname",
    "service": "$service",
    "process_id": ${process_id:-null},
    "message": "$message",
    "log_source_name": "$LOG_SOURCE_NAME",
    "user_id": "$USER_ID"
}
EOF
)
        # Send to API
        response=$(curl -s -X POST -H "Content-Type: application/json" -d "$json_payload" "$API_ENDPOINT")
        echo "$response"
    done
}

# Start both log monitoring functions
echo "Starting real-time log processing..."
process_authlogs_realtime &
process_syslogs_realtime &

# Keep the script running
wait
