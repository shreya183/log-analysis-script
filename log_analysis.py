import re
import csv
from collections import defaultdict

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_by_ip(log_lines):
    ip_counts = defaultdict(int)
    for line in log_lines:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip_counts[match.group(1)] += 1
    return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

def most_frequent_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        match = re.search(r'"(GET|POST|PUT|DELETE) (.*?) HTTP/1\.\d"', line)
        if match:
            endpoint = match.group(2)
            endpoint_counts[endpoint] += 1
    most_accessed = max(endpoint_counts.items(), key=lambda x: x[1])
    return most_accessed

def detect_suspicious_activity(log_lines):
    failed_attempts = defaultdict(int)
    for line in log_lines:
        if "401" in line or "Invalid credentials" in line:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if match:
                failed_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

def save_results_to_csv(results, file_name):
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP Requests
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in results['ip_requests'].items():
            writer.writerow([ip, count])
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow(results['most_accessed_endpoint'])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in results['suspicious_activity'].items():
            writer.writerow([ip, count])

def main():
    log_file_path = "sample.log"
    log_lines = parse_log_file(log_file_path)
    
    # Analyze log data
    ip_requests = count_requests_by_ip(log_lines)
    most_accessed_endpoint = most_frequent_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)
    
    # Display results in terminal
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    results = {
        'ip_requests': ip_requests,
        'most_accessed_endpoint': most_accessed_endpoint,
        'suspicious_activity': suspicious_activity
    }
    save_results_to_csv(results, "log_analysis_results.csv")
    print("\nResults saved to log_analysis_results.csv")

if __name__ == "__main__":
    main()
