import csv
from collections import Counter, defaultdict


# Parses the log file and extracts data
def parse_log_file(file_path):
    logs = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.split()
                if len(parts) > 6:  # Ensure the line contains sufficient elements
                    logs.append({
                        'ip': parts[0],
                        'endpoint': parts[6],
                        'status': parts[8] if len(parts) > 8 else None
                    })
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    return logs


# Count requests per IP
def count_requests_per_ip(logs):
    ip_counts = Counter(log['ip'] for log in logs)
    return ip_counts.most_common()


# Identify the most frequently accessed endpoint
def most_frequent_endpoint(logs):
    endpoint_counts = Counter(log['endpoint'] for log in logs)
    return endpoint_counts.most_common(1)[0]


# Detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_attempts = defaultdict(int)
    for log in logs:
        if log['status'] == '401':  # Assuming '401' represents a failed login
            failed_attempts[log['ip']] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > threshold}


# Save results to CSV
def save_to_csv(ip_counts, top_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)

        # Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_counts)
        writer.writerow([])

        # Most Accessed Endpoint
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([top_endpoint[0], top_endpoint[1]])
        writer.writerow([])

        # Suspicious Activity
        writer.writerow(['Suspicious Activity Detected'])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        writer.writerows(suspicious_ips.items())


# Main function
def main():
    log_file = 'sample.log.txt'  # Path to the log file
    output_file = 'log_analysis_results.csv'

    logs = parse_log_file(log_file)
    if not logs:
        return

    # 1. Count requests per IP
    ip_counts = count_requests_per_ip(logs)
    print("IP Address           Request Count")
    for ip, count in ip_counts:
        print(f"{ip:<20} {count}")

    # 2. Most frequently accessed endpoint
    top_endpoint = most_frequent_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{top_endpoint[0]} (Accessed {top_endpoint[1]} times)")

    # 3. Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # 4. Save results to CSV
    save_to_csv(ip_counts, top_endpoint, suspicious_ips, output_file)
    print(f"\nResults saved to '{output_file}'")


if __name__ == '__main__':
    main()
