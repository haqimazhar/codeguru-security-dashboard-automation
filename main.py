import json
import boto3
import requests
from datetime import datetime, timedelta
import os

CLICKUP_API_URL = os.getenv("CLICKUP_API_URL")
CLICKUP_API_TOKEN = os.getenv("CLICKUP_API_TOKEN")
CUSTOM_FIELD_ID = os.getenv("CUSTOM_FIELD_ID")
LIST_ID = os.getenv("LIST_ID")
ASSIGNEE_IDS = os.getenv("ASSIGNEE_IDS")
SCAN_NAME = os.getenv("SCAN_NAME")

SEVERITY_MAPPING = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low"
}

codeguru_client = boto3.client('codeguru-security')

# Fetch all existing ClickUp task hashes
def fetch_existing_hashes():
    url = f"https://api.clickup.com/api/v2/list/{LIST_ID}/task?include_closed=true"
    headers = {
        "Authorization": CLICKUP_API_TOKEN,
        "Accept": "application/json"
    }

    hashes = set()
    page = 0
    while True:
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
        for task in tasks:
            custom_fields = task.get("custom_fields", [])
            for field in custom_fields:
                if field["id"] == CUSTOM_FIELD_ID and field.get("value"):
                    hashes.add(field["value"])

        if data.get("last_page", False):
            break

        page += 1

    print(f"Fetched {len(hashes)} unique hashes from ClickUp.")
    return hashes

def calculate_due_date(priority):
    days_to_add = {
        1: 3,    # Critical
        2: 30,   # High
        3: 60,   # Medium
        4: 90    # Low
    }.get(priority, 90)
    due_date = datetime.now() + timedelta(days=days_to_add)
    return int(due_date.timestamp() * 1000)

def map_severity_to_priority(severity):
    severity_mapping = {
        "Critical": 1,
        "High": 2,
        "Medium": 3,
        "Low": 4,
        "Info": 4
    }
    return severity_mapping.get(severity, 4)

# Fetch findings from AWS CodeGuru Security
def fetch_codeguru_findings(scan_name):
    findings = []
    next_token = None

    while True:
        params = {"scanName": scan_name, "status": "Open", "maxResults": 100}
        if next_token:
            params["nextToken"] = next_token

        response = codeguru_client.get_findings(**params)
        findings.extend(response.get("findings", []))
        next_token = response.get("nextToken")
        if not next_token:
            break

    print(f"Fetched {len(findings)} findings from CodeGuru Security.")
    return findings

# Create a ClickUp task
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

# Process CodeGuru findings and create tasks in ClickUp
def process_findings(findings,existing_hashes):
    paginator = codeguru_client.get_paginator("get_findings")
    findings_iterator = paginator.paginate(
        scanName=SCAN_NAME,
        status="Open"
    )

    for page in findings_iterator:
        findings = page.get("findings", [])
        for finding in findings:
            finding_id = finding["id"]
            severity = finding["severity"]
            rule_id = finding["ruleId"]
            description = finding["description"]
            resource_path = finding["vulnerability"]["filePath"]["path"]
            start_line = finding["vulnerability"]["filePath"]["startLine"]
            end_line = finding["vulnerability"]["filePath"]["endLine"]

            # Skip task creation if the finding ID exists
            if finding_id in existing_hashes:
                print(f"Skipping task creation for finding ID: {finding_id} (already exists)")
                continue

            # Map severity to priority
            priority = map_severity_to_priority(severity)

            # Calculate the due date based on the priority
            due_date = calculate_due_date(priority)

            # Create task data
            task_data = {
                "name": finding["title"],
                "description": (
                    f"File path: {resource_path}` (Lines: {start_line}-{end_line})\n\n"
                    f"Description: {description}\n\n"
                ),
                "tags": [rule_id],
                "priority": priority,
                "due_date": due_date,
                "assignees": [ASSIGNEE_IDS],
                "custom_fields": [
                    {
                        "id": CUSTOM_FIELD_ID,
                        "value": finding_id
                    }
                ]
            }
            create_task(task_data)

def fetch_and_count_tasks_by_severity():
    url = f"https://api.clickup.com/api/v2/list/{LIST_ID}/task?statuses[]=to%20do&statuses[]=in%20progress"
    headers = {
        "Authorization": CLICKUP_API_TOKEN,
        "Accept": "application/json"
    }

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    page = 0
    while True:
        paginated_url = f"{url}&page={page}"
        response = requests.get(paginated_url, headers=headers)

        if response.status_code != 200:
            print(f"Error fetching tasks: {response.status_code}, {response.text}")
            return

        data = response.json()
        tasks = data.get("tasks", [])

        for task in tasks:
            priority_data = task.get("priority")
            print(priority_data)

            if isinstance(priority_data, dict) and "id" in priority_data:
                priority = int(priority_data["id"])
                print(priority)  
            else:
                priority = None  # Handle missing priority

            severity = SEVERITY_MAPPING.get(priority, "Low")  
            print(severity)
            severity_counts[severity] += 1

        if data.get("last_page", False):
            break

        page += 1  # Fetch next page

    print("\nTask Count by Severity (To-Do & In Progress):")
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")
        print(f'::set-output name=severity::{count}')


    


# Main function
def main():

    existing_hashes = fetch_existing_hashes()
    findings = fetch_codeguru_findings(SCAN_NAME)
    process_findings(findings, existing_hashes)
    fetch_and_count_tasks_by_severity()

if __name__ == "__main__":
    main()