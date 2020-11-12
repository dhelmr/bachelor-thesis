import dpkt

from canids.dataset_utils.pcap_utils import get_ip_packet

reader = dpkt.pcap.Reader(open("test.pcap", "rb"))

for ts, buf in reader:
    ip = get_ip_packet(buf)
    print(ip)
