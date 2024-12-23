# Log Analysis Script

## Overview
This repository contains a Python script designed to analyze server log files, extracting and summarizing key insights. It demonstrates proficiency in file handling, string manipulation, and data analysis using Python.

## Features
1. **Request Counts by IP Address**  
   - Parses the log file to extract IP addresses.  
   - Counts the number of requests made by each IP and sorts the results in descending order.

2. **Most Frequently Accessed Endpoint**  
   - Identifies the most accessed endpoint in the log file.  
   - Displays the endpoint and the number of times it was accessed.

3. **Suspicious Activity Detection**  
   - Tracks failed login attempts (e.g., HTTP 401 status codes or "Invalid credentials").  
   - Flags IP addresses exceeding a configurable threshold of failed login attempts (default: 10).

4. **Output**  
   - Results are displayed in the terminal for immediate review.  
   - A CSV file, `log_analysis_results.csv`, is generated containing:  
      - Request counts by IP address.  
      - The most frequently accessed endpoint.  
      - Suspicious activity detection results.

## Files in this Repository
- `log_analysis.py`: The main Python script for log analysis.
- `sample.log`: A sample log file used for testing the script.
- `log_analysis_results.csv`: An example output file generated by the script.
