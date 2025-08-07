# CovDetect
This tool analyzes network packet captures (.pcap/.pcapng files) to detect possible covert channels. It evaluates packet fields like TTL, TCP sequence numbers, IP IDs, payload sizes, and inter-packet delays.  It generates visual graphs, entropy scores, CSV summaries, and a plain text report for every analysis. 


How to Run
Requirements (for Python version):
pip install pyshark matplotlib termcolor
Or use the EXE version if provided.

Usage
After starting the tool, you’ll be prompted with:
1. Analyze a single PCAP file
2. Analyze all PCAPs in a folder
3. Exit

Option 1: Input full file path to a .pcap or .pcapng file.
Option 2: Input a folder path. All valid capture files in that folder will be processed.

What It Analyzes
Field	Purpose
TTL	Histogram and entropy of IP Time-to-Live values
TCP Sequence	Detects repetition or low entropy in sequence numbers
IP ID	Analyzes value jumps and sequential behavior
Payload Size	Checks for binary encoding via payload sizes
Inter-Packet Delay	Detects timing-based covert channels

Output Files
Each analyzed file generates:

- A TXT report: e.g., sample_results_YYYYMMDD_HHMMSS.txt
- A CSV file with raw counts and field values
- A PNG image with histograms and plots

These are saved in the working directory.

Suspicious Activity Flags
- High TTL repetition: indicates timing/steganography
- Sequential IP ID values: may signal binary encoding
- Repeated TCP SEQs: possible packet reuse or LSB encoding
- Very low timing jitter: classic sign of timing covert channels


Student Tips
- Look for strange uniformity in graphs
- TTLs toggling between two values? That’s suspicious
- TCP SEQs jumping non-linearly? That’s data hiding
- If entropy is too low or too high, dig deeper

Good To Know
This tool is for education only and should be used ethically. It demonstrates how covert data can sneak through normal-looking network traffic.
