import hashlib
import json
import requests
from datetime import datetime, timedelta

# Constants
# Fetch environment variables
CLICKUP_API_URL = os.getenv("CLICKUP_API_URL")
CLICKUP_API_TOKEN = os.getenv("CLICKUP_API_TOKEN")
CUSTOM_FIELD_ID = os.getenv("CUSTOM_FIELD_ID")
LIST_ID = os.getenv("LIST_ID")
ASSIGNEE_IDS = list(map(int, os.getenv("ASSIGNEE_IDS").split(',')))  # Convert to a list of integers

# Function to fetch all tasks and extract custom field values
def fetch_existing_hashes():
    url = f"https://api.clickup.com/api/v2/list/{LIST_ID}/task?include_closed=true"
    headers = {
        "Authorization": CLICKUP_API_TOKEN,
        "Accept": "application/json"
    }

    hashes = set()
    page = 0
    while True:
        # Append the page number as a query parameter
        paginated_url = f"{url}&page={page}"
        response = requests.get(paginated_url, headers=headers)

        if response.status_code != 200:
            print(f"Error fetching tasks: {response.status_code}, {response.text}")
            break

        try:
            data = response.json()
        except ValueError:
            print("Error: Unable to parse JSON response")
            break

        tasks = data.get("tasks", [])
        if not tasks:
            print("No tasks found on the current page.")
            break

        for task in tasks:
            custom_fields = task.get("custom_fields", [])
            for field in custom_fields:
                if field["id"] == CUSTOM_FIELD_ID and field.get("value"):
                    hashes.add(field["value"])

        if data.get("last_page", False):  # Check if this is the last page
            break

        page += 1  # Increment page for the next request

    print(f"Fetched {len(hashes)} unique hashes from ClickUp.")
    return hashes

# Function to create a hash for a finding
def generate_hash(rule_id, file_path, start_line, end_line):
    data = f"{rule_id}:{file_path}:{start_line}:{end_line}"
    return hashlib.md5(data.encode()).hexdigest()

# Function to create a ClickUp task
def create_task(task_data):
    headers = {
        "Authorization": CLICKUP_API_TOKEN,
        "Content-Type": "application/json"
    }
    response = requests.post(
        CLICKUP_API_URL.format(list_id=LIST_ID),
        headers=headers,
        data=json.dumps(task_data)
    )
    if response.status_code == 200:
        print(f"Task created successfully: {task_data['name']}")
    else:
        print(f"Error creating task: {response.status_code}, {response.text}")

# Build a rule map for faster lookups
def build_rule_map(sarif_data):
    rule_map = {}
    for rule in sarif_data["runs"][0]["tool"]["driver"]["rules"]:
        rule_id = rule["id"]
        short_description = rule["shortDescription"]["text"]
        severity = float(rule["properties"].get("security-severity", 0))
        rule_map[rule_id] = {
            "short_description": short_description,
            "severity": severity
        }
    return rule_map

# Function to categorize severity
def map_severity(severity):
    if severity == 0:
        return 4  # None or Info
    elif 0.1 <= severity < 4.0:
        return 4  # Low
    elif 4.0 <= severity < 7.0:
        return 3  # Medium
    elif 7.0 <= severity < 9.0:
        return 2  # High
    elif severity >= 9.0:
        return 1  # Critical
    else:
        return 4  # Default to low

# Function to calculate the due date based on priority
def calculate_due_date(priority):
    days_to_add = {
        1: 3,    # Critical
        2: 30,   # High
        3: 60,   # Medium
        4: 90    # Low
    }.get(priority, 90)  # Default to 90 days for unknown priorities

    due_date = datetime.now() + timedelta(days=days_to_add)
    return int(due_date.timestamp() * 1000) 

# Process the SARIF file
def process_sarif(file_path, existing_hashes):
    with open(file_path, "r") as file:
        sarif_data = json.load(file)

    rule_map = build_rule_map(sarif_data)

    findings = []
    for result in sarif_data["runs"][0]["results"]:
        rule_id = result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        file_uri = location["artifactLocation"]["uri"]
        start_line = location["region"]["startLine"]
        end_line = location["region"]["endLine"]
        description = result["message"]["text"]

        rule_details = rule_map.get(rule_id, {"short_description": f"Unknown issue: {rule_id}", "severity": 0})
        short_description = rule_details["short_description"]
        severity = rule_details["severity"]
        priority = map_severity(severity)

        finding_hash = generate_hash(rule_id, file_uri, start_line, end_line)

        if finding_hash in existing_hashes:
            print(f"Skipping task creation for hash: {finding_hash} (already exists)")
            continue

        due_date = calculate_due_date(priority)

        task_data = {
            "name": short_description,
            "description": f"Vulnerability in `{file_uri}` (Lines: {start_line}-{end_line})\n\n{description}",
            "tags": [rule_id],
            "priority": priority,
            "due_date": due_date,
            "assignees": ASSIGNEE_IDS,
            "include_closed": True,
            "custom_fields": [
                {
                    "id": CUSTOM_FIELD_ID,
                    "value": finding_hash
                }
            ]
        }
        findings.append(task_data)

    return findings

# Main function
def main():
    sarif_file = "./codeguru-security-results.sarif 2.json"
    existing_hashes = fetch_existing_hashes()
    print(f"Existing hashes: {existing_hashes}")

    findings = process_sarif(sarif_file, existing_hashes)

    for task in findings:
        create_task(task)

if __name__ == "__main__":
    main()