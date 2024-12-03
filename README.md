# Log Analysis Script

## Overview

This Python script analyzes server log data to extract valuable insights. It performs the following tasks:
- Counts the number of requests made by each IP address.
- Identifies the most frequently accessed endpoint.
- Detects suspicious activity by flagging IP addresses with a high number of failed login attempts.

## Features

1. **Count Requests per IP Address**:
    - Parses the log file to extract IP addresses and their respective request counts.
    - Outputs the results sorted in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**:
    - Extracts endpoint data from the logs and identifies the most accessed endpoint.
    - Displays the endpoint and its access count.

3. **Detect Suspicious Activity**:
    - Detects failed login attempts (HTTP status code `401` or specific error messages).
    - Flags IP addresses with failed login attempts exceeding a configurable threshold.

4. **Results Output**:
    - Displays results in the terminal in a clear and organized format.
    - Saves the results to a CSV file (`log_analysis_results.csv`) with the following columns:
        - `Requests per IP`: IP Address, Request Count
        - `Most Accessed Endpoint`: Endpoint, Access Count
        - `Suspicious Activity`: IP Address, Failed Login Count

## Prerequisites

- Python 3.x
- Required Python libraries: `csv`, `re`

## How to Run

1. Clone this repository or download the script file `log_analysis.py`.
2. Prepare a log file (`sample.log.txt`) containing the server logs in the same directory as the script.
3. Run the script using the following command:

    ```bash
    python log_analysis.py
    ```

4. The results will be displayed in the terminal and saved to `log_analysis_results.csv`.

## Example Output

### Requests per IP Address:
```bash
IP Address           Request Count
203.0.113.5         8
198.51.100.23       8
192.168.1.1         7
10.0.0.2            6
192.168.1.100       5
