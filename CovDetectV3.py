import pyshark
import argparse
from collections import Counter
import csv
from datetime import datetime
import os
import math
import matplotlib.pyplot as plt
from termcolor import colored


# Signature block
CREATOR_TAG = """
Created by: Ashley Smith
Team 6 // CS4463
Date: 2025
File: CovDetectV3.py
"""
# 🌈 Fancy rainbow title because... why not?


def rainbow_banner(text):
    # Just print the banner letters one by one with rainbow colors
    colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']
    rainbow_text = ""

    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        rainbow_text += colored(char, color)

    return rainbow_text + "\n"

# 🤓 Math stuff to detect sneaky data
def calculate_entropy(data):
    total = len(data)
    if total == 0:
        return 0.0
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())

# 📊 Making some cool charts
def generate_graphs(base_name, ttl_values, ip_ids, tcp_seqs, id_diffs, payload_lengths):
    plt.figure(figsize=(16, 10))

     # TTL histogram - Time To Live values (ironically, they're already dead)
    plt.subplot(3, 2, 1)
    plt.hist(ttl_values, bins=range(min(ttl_values), max(ttl_values) + 1), color='skyblue', edgecolor='black')
    plt.title("TTL Distribution")

    # TCP sequence numbers - because order matters (sometimes)
    plt.subplot(3, 2, 2)
    plt.hist(tcp_seqs, bins=20, color='lightgreen', edgecolor='black')
    plt.title("TCP Sequence Numbers")

    # IP ID values - every packet needs an ID card
    plt.subplot(3, 2, 3)
    plt.hist(ip_ids, bins=20, color='salmon', edgecolor='black')
    plt.title("IP ID Values")

    # IP ID differences - spotting patterns like a detective
    plt.subplot(3, 2, 4)
    plt.plot(id_diffs[:50], marker='o', linestyle='-', color='purple')
    plt.title("First 50 IP ID Differences")

    # Payload sizes - size matters (for packets)
    if payload_lengths:
        plt.subplot(3, 2, 5)
        plt.hist(payload_lengths, bins=10, color='gold', edgecolor='black')
        plt.title("Payload Size Distribution")

    plt.tight_layout()
    graph_file = f"{base_name}_graphs_v2.png"
    plt.savefig(graph_file)
    plt.close()
    return graph_file

def analyze_pcap(pcap_file):
    # Print a message indicating the beginning of analysis, with the pcap file name 
    print(colored(f"Analyzing {pcap_file}...(this might take a hot minute)", "cyan"))
    
    # Create a pyshark FileCapture object, which reads packets from the specified pcap file.
    cap = pyshark.FileCapture(pcap_file)
    
    # Initialize lists to store different packet attributes for analysis.
    ttl_values = []          # Time-to-Live values of packets
    ip_ids = []              # IP identifiers
    tcp_seqs = []            # TCP sequence numbers
    sniff_times = []         # Times at which packets were captured
    payload_lengths = []     # Lengths of the payload contained in packets

    # Loop through every packet like we're reading a very technical novel
    for pkt in cap:
        try:
            # If this packet has IP layer (most do, unless they're weird)
            if 'IP' in pkt:
                ttl_values.append(int(pkt.ip.ttl))
                ip_ids.append(int(pkt.ip.id, 16)) # Convert hex ID to decimal (because math)
                
                # Calculate payload length - it's like packet weight watching
                if hasattr(pkt, 'length'):
                    total_len = int(pkt.length) # Total packet size
                    ip_hdr_len = int(pkt.ip.hdr_len) * 4 # IP header size (multiply by 4, don't ask why)
                    
                    if 'TCP' in pkt: # If it's TCP, we need to subtract TCP header too
                        tcp_hdr_len = int(pkt.tcp.hdr_len) * 4 # TCP header size
                        payload_len = total_len - ip_hdr_len - tcp_hdr_len # What's left is payload
                        payload_lengths.append(payload_len)
            
                # Collect TCP sequence numbers (the packet order police)
                if 'TCP' in pkt:
                    tcp_seqs.append(int(pkt.tcp.seq))
                
                # Record when we caught this packet red-handed
                sniff_times.append(float(pkt.sniff_timestamp))
            
        except AttributeError:
            continue  # Skip packets that don't play by the rules

    # Time for some data crunching! 🥜
    ttl_counts = Counter(ttl_values)      # Count TTL occurrences
    seq_counts = Counter(tcp_seqs)        # Count sequence number repeats
    # Calculate differences between consecutive IP IDs (looking for patterns)
    id_diffs = [j - i for i, j in zip(ip_ids[:-1], ip_ids[1:])]
    # Calculate time delays between packets (timing analysis)
    delays = [t2 - t1 for t1, t2 in zip(sniff_times[:-1], sniff_times[1:])]
    payload_counts = Counter(payload_lengths)  # Count payload size patterns

    # Calculate entropy (randomness level) for different fields
    ttl_entropy = calculate_entropy(ttl_values)      # How random are TTLs?
    seq_entropy = calculate_entropy(tcp_seqs)        # How random are sequences?
    payload_entropy = calculate_entropy(payload_lengths)  # How random are payload sizes?

    # 🚨 Suspicious activity detection (our digital detective work)
    warnings = []
    
    # Check for TTL abuse (same TTL used way too often)
    if ttl_counts.most_common(1)[0][1] > 3:
        warnings.append("🚩 High occurrence of a single TTL - may indicate timing/steganography")
    
    # Check for sequential IP IDs (too organized to be natural)
    if all(diff == 1 for diff in id_diffs[:3]):
        warnings.append("🚩 IP ID values are sequential — may encode binary data")
    
    # Check for repeated TCP sequence numbers (déjà vu much?)
    if seq_counts.most_common(1)[0][1] > 1:
        warnings.append("🚩 Repeated TCP sequence number detected")
    
    # Check for suspiciously consistent timing (robots don't vary much)
    if len(delays) >= 5:
        mean_delay = sum(delays) / len(delays)  # Average delay
        # Calculate standard deviation (how much variation there is)
        std_dev = (sum((d - mean_delay) ** 2 for d in delays) / len(delays)) ** 0.5
        if std_dev < 0.0005:  # If timing is too consistent
            warnings.append("🚩 Very low timing jitter — possible timing-based covert channel")

    # Convert TTL values to binary pattern (even/odd = 0/1)
    # Because sometimes people hide messages in the least significant bits
    ttl_bits = ''.join(['0' if ttl % 2 == 0 else '1' for ttl in ttl_values])

    # Generate unique filenames with timestamps (because organization matters)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(os.path.basename(pcap_file))[0]  # Get filename without extension
    txt_log = f"{base_name}_results_{timestamp}.txt"
    csv_log = f"{base_name}_results_{timestamp}.csv"

    # Write human-readable report (for the story lovers)
    with open(txt_log, "w", encoding="utf-8") as log:
        log.write(f"📋 Analysis Report for: {pcap_file}\n")
        log.write("=" * 50 + "\n")
        log.write("--- Analysis Summary ---\n\n")
        log.write(f"🏆 Most Common TTLs: {ttl_counts.most_common(3)}\n")
        log.write(f"🎲 TTL Entropy: {ttl_entropy:.4f}\n")
        log.write(f"🎲 SEQ Entropy: {seq_entropy:.4f}\n")
        log.write(f"🎲 Payload Size Entropy: {payload_entropy:.4f}\n")
        log.write(f"📦 Most Common Payload Sizes: {payload_counts.most_common(3)}\n")
        log.write(f"💾 TTL Binary Pattern (first 16 bits): {ttl_bits[:16]}\n\n")
        
        # Write any suspicious findings
        if warnings:
            log.write("⚠️  POTENTIAL ISSUES DETECTED:\n")
            for warn in warnings:
                log.write(f"   {warn}\n")
        else:
            log.write("✅ No obvious covert channels detected!\n")

    # Write machine-readable CSV (for the data nerds)
    with open(csv_log, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Field", "Value", "Count"])  # Header row
        
        # Write TTL data
        for ttl, count in ttl_counts.items():
            writer.writerow(["TTL", ttl, count])
            
        # Write TCP sequence data
        for seq, count in seq_counts.items():
            writer.writerow(["TCP_SEQ", seq, count])
            
        # Write payload size data
        for size, count in payload_counts.items():
            writer.writerow(["Payload_Size", size, count])
            
        # Write IP ID differences (first 5 only - we're not writing a novel)
        for idx, diff in enumerate(id_diffs[:5]):
            writer.writerow(["IP_ID_DIFF", f"diff{idx}", diff])
            
        # Write timing delays (first 5 only)
        for idx, delay in enumerate(delays[:5]):
            writer.writerow(["Inter_Packet_Delay", f"delay{idx}", delay])

    # Generate pretty graphs (because visualization is everything)
    graph_path = generate_graphs(base_name, ttl_values, ip_ids, tcp_seqs, id_diffs, payload_lengths)

    # Victory lap! Tell the user what we accomplished
    print(colored(f"\n📝 Summary written to {txt_log}", "green"))
    print(colored(f"📊 Detailed data written to {csv_log}", "green"))
    print(colored(f"📈 Graphs saved to {graph_path}", "green"))
    print(colored("✅ Analysis complete. You're welcome! 🎉\n", "green"))

# Get all PCAP files from a folder (batch processing like a boss)
def get_pcap_files_from_folder(folder_path):
    # Return list of all .pcap and .pcapng files in the folder
    return [os.path.join(folder_path, f) for f in os.listdir(folder_path) 
            if f.endswith('.pcap') or f.endswith('.pcapng')]

def main():
    # Show off with our fancy rainbow banner
    print(rainbow_banner("Covert Channel Detector"))
    print(colored(CREATOR_TAG, "cyan"))
    print(colored("🕵️ Ready to catch some sneaky network behavior!", "yellow"))

    # Main program loop (because we're user-friendly like that)
    while True:
        print("\n" + "="*40)
        print("🎯 Choose your adventure:")
        print("1. 🔍 Analyze a single PCAP file")
        print("2. 📁 Analyze all PCAPs in a folder")
        print("3. 🚪 Exit (and go touch grass)")
        
        choice = input("\n👉 Your choice: ").strip()

        if choice == '1':
            # Single file analysis
            pcap = input("📂 Enter full path to the PCAP file (e.g., C:/Users/You/Documents/test.pcap): ").strip()
            if os.path.isfile(pcap):
                analyze_pcap(pcap)
            else:
                print(colored("❌ Invalid file path. Did you typo? Try again!", "red"))

        elif choice == '2':
            # Batch folder analysis (for the overachievers)
            folder = input("📁 Enter path to the folder with PCAP files: ").strip()
            if os.path.isdir(folder):
                pcaps = get_pcap_files_from_folder(folder)
                if not pcaps:
                    print(colored("😞 No PCAP files found in the folder. Wrong folder?", "red"))
                else:
                    print(colored(f"🎉 Found {len(pcaps)} PCAP files. Let's analyze them all!", "green"))
                    for p in pcaps:
                        analyze_pcap(p)
                    print(colored("🏁 Batch analysis complete! Time for coffee ☕", "green"))
            else:
                print(colored("❌ Invalid folder path. Check your typing!", "red"))

        elif choice == '3':
            # Graceful exit
            print(colored("👋 Goodbye! Thanks for using the Covert Channel Detector!", "cyan"))
            print(colored("🕵️ Keep those networks secure! 🔒", "yellow"))
            break

        else:
            # Handle invalid input (because users will be users)
            print(colored("🤔 Invalid selection. Please enter 1, 2, or 3. Reading is fundamental!", "red"))

# The sacred Python incantation
if __name__ == "__main__":
    main()