import typing as t

import numpy as np
import pyshark

from anomaly_detection.types import FeatureExtractor, TrafficType


class BasicPacketFeatureExtractor(FeatureExtractor):

    def extract_features(self, pcap_file: str) -> np.ndarray:
        return self._extract_features(pcap_file, True)

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        return de_result

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        return self._extract_features(pcap_file, False)

    def _extract_features(self, pcap_file: str, prepare_backwards_mapping: bool):
        features = []
        packets = pyshark.FileCapture(pcap_file, keep_packets=False)
        for pkt in packets:
            if "ip" not in pkt:
                features.append([-1, -1, -1])
                continue
            src_ip = int(pkt.ip.src.replace(".", ""))  # TODO!!! handle ip formats like 8.23.123.2 vs 8.231.2.32
            dest_ip = int(pkt.ip.dst.replace(".", ""))
            if "tcp" in pkt:
                src_port = int(pkt.tcp.port)
                dest_port = int(pkt.tcp.dstport)
                protocol = 6
            elif "udp" in pkt:
                src_port = int(pkt.udp.port)
                dest_port = int(pkt.udp.dstport)
                protocol = 17
            else:
                src_port = 0
                dest_port = 0
                protocol = 0
            features.append([src_port, dest_port, protocol])
            # TODO add more features
        return np.array(features)

    def get_name(self) -> str:
        return "basic_packet_feature_extractor"
