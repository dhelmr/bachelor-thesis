import logging
import socket
from typing import Optional

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


def get_ip_packet(buf, linklayer_hint=None) -> Optional[dpkt.ip.IP]:
    if linklayer_hint is not None:
        pkt = linklayer_hint(buf)
        if type(pkt.data) is dpkt.ip.IP:
            return pkt.data
    else:
        for linklayer_proto in [dpkt.ethernet.Ethernet, dpkt.sll.SLL]:
            pkt = linklayer_proto(buf)
            if type(pkt.data) is dpkt.ip.IP:
                return pkt.data
    return None


class FlowIDFormatter:
    def __init__(self, protocol_encodings):
        self.protocol_encodings = protocol_encodings

    def make_flow_ids(self, ts, buf, packet_type=dpkt.ethernet.Ethernet):
        ip = get_ip_packet(buf, linklayer_hint=packet_type)
        if ip is None:
            return None
        src_ip = socket.inet_ntoa(ip.src)
        dest_ip = socket.inet_ntoa(ip.dst)
        if type(ip.data) is dpkt.tcp.TCP:
            src_port = int(ip.tcp.sport)
            dest_port = int(ip.tcp.dport)
            protocol = self.protocol_encodings["tcp"]
        elif type(ip.data) is dpkt.udp.UDP:
            src_port = int(ip.udp.sport)
            dest_port = int(ip.udp.dport)
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


class SubsetPacketReader:
    def __init__(self, pcap_path: str, ranges):
        self.pcap_path = pcap_path
        self.ranges = ranges

    def __iter__(self):
        reader = read_pcap_pcapng(self.pcap_path)
        i = -1
        range_index = 0
        start, end = self.ranges[range_index]
        for packet in reader:
            i += 1
            if i < start:
                continue
            if end != "end" and i >= end:
                range_index += 1
                if len(self.ranges) <= range_index:
                    break
                start, end = self.ranges[range_index]
                continue
            yield packet
