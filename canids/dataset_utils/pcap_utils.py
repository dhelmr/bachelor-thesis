import logging
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
