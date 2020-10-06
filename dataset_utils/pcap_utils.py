import logging
import socket

import dpkt as dpkt


def read_pcap_pcapng(file, print_progress_after=None):
    try:
        reader = dpkt.pcapng.Reader(open(file, "rb"))
    except ValueError as e:
        reader = dpkt.pcap.Reader(open(file, "rb"))
    progress = 0
    for packet in reader:
        yield packet

        if print_progress_after is None:
            continue
        progress += 1
        if progress % print_progress_after == 0:
            logging.info("%s: Processed %s packets", file, progress)


class FlowIDFormatter:
    def __init__(self, protocol_encodings):
        self.protocol_encodings = protocol_encodings

    def make_flow_ids(self, ts, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) is not dpkt.ip.IP:
            return None
        src_ip = socket.inet_ntoa(eth.ip.src)
        dest_ip = socket.inet_ntoa(eth.ip.dst)
        if type(eth.ip.data) is dpkt.tcp.TCP:
            src_port = int(eth.ip.tcp.sport)
            dest_port = int(eth.ip.tcp.dport)
            protocol = self.protocol_encodings["tcp"]
        elif type(eth.ip.data) is dpkt.udp.UDP:
            src_port = int(eth.ip.udp.sport)
            dest_port = int(eth.ip.udp.dport)
            protocol = self.protocol_encodings["udp"]
        else:
            src_port = 0
            dest_port = 0
            protocol = self.protocol_encodings["unknown"]
        return [self.format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol),
                self.format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=True)]

    def format_flow_id(self, src_ip, dest_ip, src_port, dest_port, protocol, reverse=False):
        if not reverse:
            return "%s-%s-%s-%s-%s" % (src_ip, dest_ip, src_port, dest_port, protocol)
        return "%s-%s-%s-%s-%s" % (dest_ip, src_ip, dest_port, src_port, protocol)
