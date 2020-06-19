import logging
import typing as t

import dpkt
import numpy as np

from anomaly_detection.types import FeatureExtractor, TrafficType
from dataset_utils.pcap_utils import read_pcap_pcapng


class BasicPacketFeatureExtractor(FeatureExtractor):

    def extract_features(self, pcap_file: str) -> np.ndarray:
        return self._extract_features(pcap_file, True)

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        return de_result

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        return self._extract_features(pcap_file, False)

    def _extract_features(self, pcap_file: str, prepare_backwards_mapping: bool):
        packets = read_pcap_pcapng(pcap_file)
        feature_matrix = []
        progress = 0
        for ts, buf in packets:
            feature_matrix.append(self.analyze_packet(ts, buf))
            progress += 1
            if progress % 500_000 == 0:
                logging.info("Processed %s packets for meta features extraction", progress)
        return np.array(feature_matrix)

    def analyze_packet(self, timestamp, buffer):
        udp_features = [0, 0, 0]
        tcp_features = [0, 0, 0, 0]
        src_port = -1000
        dest_port = -1000
        eth = dpkt.ethernet.Ethernet(buffer)
        if type(eth.data) is not dpkt.ip.IP:
            src_ip = -1000
            dest_ip = -1000
        else:
            ip = eth.data
            src_ip = int.from_bytes(eth.ip.src, "big")
            dest_ip = int.from_bytes(eth.ip.dst, "big")
            if ip.data is dpkt.tcp.TCP:
                src_port = int(eth.ip.tcp.sport)
                dest_port = int(eth.ip.tcp.dport)
                tcp_ops = int.from_bytes(eth.ip.tcp.opts, "big")
                tcp_urp = eth.ip.tcp.urp
                tcp_flags = eth.ip.tcp.tcp_flags  # TODO one-hot encoding
                tcp_features = [1, tcp_ops, tcp_urp, tcp_flags]
            elif ip.data is dpkt.udp.UDP:
                src_port = int(eth.ip.udp.sport)
                dest_port = int(eth.ip.udp.dport)
                udp_features = [1, eth.ip.udp.ulen, eth.ip.udp.sum]
        feature_list = [len(eth), src_ip, dest_ip, src_port, dest_port] + tcp_features + udp_features
        return feature_list

    def get_name(self) -> str:
        return "basic_packet_feature_extractor"
