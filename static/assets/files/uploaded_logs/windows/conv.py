import re
import json

# Define the file paths
TXT_FILE_PATH = '/home/smilex/Desktop/Logs/SystemLogs.txt'
JSON_FILE_PATH = '/home/smilex/Desktop/Logs/SystemLogs.json'

def parse_log_data(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    
    # Adjust the regex pattern to handle different fields correctly
    # Assuming logs are separated by new lines and have consistent formatting
    pattern = re.compile(
        r'(?P<TimeGenerated>\S+ \S+)\s+'  # TimeGenerated (date and time)
        r'(?P<EntryType>\S+)\s+'           # EntryType
        r'(?P<Source>[\w\-\.]+)\s+'        # Source
        r'(?P<EventID>\d+)\s+'             # EventID
        r'(?P<Message>.+)', re.MULTILINE | re.DOTALL)  # Message until end of line or file

    matches = pattern.finditer(content)
    
    logs = []
    for match in matches:
        log_entry = {
            'TimeGenerated': match.group('TimeGenerated').strip(),
            'EntryType': match.group('EntryType').strip(),
            'Source': match.group('Source').strip(),
            'EventID': match.group('EventID').strip(),
            'Message': match.group('Message').strip()
        }
        logs.append(log_entry)
    
    return logs

def convert_to_json(logs, json_file_path):
    with open(json_file_path, 'w') as json_file:
        json.dump(logs, json_file, indent=4)
    print(f"Logs have been converted to JSON and saved to {json_file_path}")

def main():
    logs = parse_log_data(TXT_FILE_PATH)
    if logs:
        convert_to_json(logs, JSON_FILE_PATH)
    else:
        print("No logs found to convert.")

if __name__ == "__main__":
    main()

