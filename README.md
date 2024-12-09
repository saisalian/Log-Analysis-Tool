# Log Analysis Tool
A Python-based tool to parse, analyze, and report on logs for security incident detection.

## Features
- Ingest logs from Apache/NGINX and JSON formats
- Detect malicious patterns and anomalies
- Generate incident reports

## Project Structure
- `src/`: Contains code modules
- `logs/`: Stores log files for analysis
- `tests/`: Contains test scripts

## Log Ingestion
The tool currently supports:
- Parsing Apache/NGINX logs using regex.
- Parsing JSON logs into a structured format using the `json` library.
