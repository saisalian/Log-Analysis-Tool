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
    # Filter rows with status codes 403 or 500
    suspicious_statuses = ["403", "500"]
    return df[df["status"].isin(suspicious_statuses)]



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
