import os
import re
import pandas as pd
import json

def read_apache_logs(file_path):
    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - '
        r'\[(?P<datetime>.+?)\] '
        r'"(?P<method>[A-Z]+) (?P<url>.+?) HTTP/\d+\.\d+" '
        r'(?P<status>\d+) (?P<size>\d+)'
    )
    log_entries = []

    print(f"Looking for file at: {os.path.abspath(file_path)}")

    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                log_entries.append(match.groupdict())
    
    return pd.DataFrame(log_entries)

def filter_suspicious_apache_logs(df):
    # Define suspicious criteria
    suspicious_statuses = ["403", "500", "404", "401"]  # Common suspicious status codes
    suspicious_methods = ["PUT", "DELETE"]  # Potentially dangerous HTTP methods
    suspicious_urls = ["/admin", "/login", "/wp-admin", "/config", "/backup"]  # High-risk URLs

    # Filter logs based on criteria
    suspicious_df = df[
        (df["status"].isin(suspicious_statuses)) |  # Check for suspicious statuses
        (df["method"].isin(suspicious_methods)) |  # Check for suspicious methods
        (df["url"].str.contains("|".join(suspicious_urls), case=False, na=False))  # Check for suspicious URLs
    ]
    
    return suspicious_df

def read_json_logs(file_path):
    log_entries = []

    print(f"Looking for file at: {os.path.abspath(file_path)}")

    with open(file_path, 'r') as file:
        for line in file:
            try:
                log_entry = json.loads(line.strip())
                log_entries.append(log_entry)
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON: {e}, Line: {line}")
    
    return pd.DataFrame(log_entries)

def filter_suspicious_json_logs(df):
    # Check if the necessary columns exist in the DataFrame
    if "level" in df.columns:
        suspicious_df = df[
            (df["level"] == "ERROR") |
            (df["message"].str.contains("failed|unauthorized|denied", case=False, na=False))
        ]
    else:
        # Filter only based on message if 'level' is missing
        suspicious_df = df[
            df["message"].str.contains("failed|unauthorized|denied", case=False, na=False)
        ]
    return suspicious_df

def generate_incident_report(apache_df, json_df, output_path="incident_report.md"):

    with open(output_path, 'w') as report:
        report.write("# Incident Report\n")
        report.write("This report summarizes suspicious activities detected in logs.\n\n")

        # Apache logs section
        report.write("## Suspicious Apache Logs\n")
        if apache_df.empty:
            report.write("No suspicious Apache logs found.\n")
        else:
            report.write(apache_df.to_markdown(index=False) + "\n\n")

        # JSON logs section
        report.write("## Suspicious JSON Logs\n")
        if json_df.empty:
            report.write("No suspicious JSON logs found.\n")
        else:
            report.write(json_df.to_markdown(index=False) + "\n\n")
    
    print(f"Incident report generated at: {output_path}")

if __name__ == "__main__":
    print(f"Current working directory: {os.getcwd()}")

    # Apache logs
    apache_logs_path = "C:/Log_Analysis_Tool/logs/apache_logs/sample_access.log"
    apache_df = read_apache_logs(apache_logs_path)
    print("Apache Logs:")
    print(apache_df.head())

    # Filter suspicious Apache logs
    suspicious_apache = filter_suspicious_apache_logs(apache_df)
    print("\nSuspicious Apache Logs:")
    print(suspicious_apache)

    # JSON logs
    json_logs_path = "C:/Log_Analysis_Tool/logs/json_logs/sample_log.json"
    json_df = read_json_logs(json_logs_path)
    print("JSON Logs:")
    print(json_df.head())

    # Filter suspicious JSON logs
    suspicious_json = filter_suspicious_json_logs(json_df)
    print("\nSuspicious JSON Logs:")
    print(suspicious_json)

    # Generate incident report
    generate_incident_report(suspicious_apache, suspicious_json)
