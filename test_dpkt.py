import dpkt

# pcap_file = "data/unsw-nb15/01/1.pcap"
pcap_file = "test.pcap"
# pcap_file = "data/unsw-nb15/fixed/1.pcap"


reader = dpkt.pcap.Reader(open(pcap_file, "rb"))

non_ip_count = 0
ip_count = 0

for timestamp, buf in reader:
    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        non_ip_count += 1
        continue

    ip_count += 1

print("IP packets: %s; Non-IP packets: %s" % (ip_count, non_ip_count))
