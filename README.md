# Log Analysis Tool  
A Python-based tool to parse, analyze, and report on logs for security incident detection.

## Features  
- Ingest logs from Apache/NGINX and JSON formats  
- Detect suspicious activities based on IPs, status codes, and messages  
- Filter logs based on various patterns like `failed`, `unauthorized`, and `denied`  

## Project Structure  
- `src/`: Contains code modules  
- `logs/`: Stores log files for analysis  
- `tests/`: Contains test scripts

## Log Ingestion  
The tool currently supports:
- **Apache Logs:**  
  - Parses Apache/NGINX logs using regex to detect suspicious activities based on status codes (e.g., `403`, `500`) and failed access attempts.
  
- **JSON Logs:**  
  - Parses JSON logs into a structured format using the `json` library.
  - Filters logs based on suspicious status codes (e.g., `401`, `403`, `500`), messages containing keywords like `failed`, `unauthorized`, `denied`, and the `ERROR` level.

## Suspicious Log Detection  
- **Apache Logs:**  
  - Filters logs with suspicious status codes and potential malicious access patterns, such as unauthorized login attempts.

- **JSON Logs:**  
  - Filters logs containing the `ERROR` level or suspicious messages related to failed access attempts.
  - Detects logs with suspicious status codes (`401`, `403`, `500`).

