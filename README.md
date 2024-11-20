# Network Scanner with Data Analysis

This Python script scans a local network for active devices, displays their IP and MAC addresses, and performs data analysis on the scanned data. It uses Scapy for network scanning, Pandas for data manipulation, and Matplotlib for data visualization.

---

## Features

- Scans a specified IP range for active devices.
- Displays the IP and MAC addresses of detected devices.
- Analyzes MAC address prefixes (vendor information) and visualizes the distribution.
- Saves the scan results to a CSV file for further analysis.

---

## Prerequisites

Before running the script, ensure the following are installed on your computer:

1. **Python 3.6 or higher**  
   Verify your Python version with:
     ```bash
     python --version
     ```
     or
     ```bash
     python3 --version
     ```

2. **Required Python Libraries**  
   Install the required libraries using `pip`:
   ```bash
   pip install scapy pandas matplotlib
   ```
---
# Usage

##Running the Script
 
1.
```bash
sudo python netscan.py
```
2. 
```bash
python netscan.py
```
