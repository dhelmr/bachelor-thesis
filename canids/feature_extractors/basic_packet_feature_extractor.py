import argparse
import logging
import typing as t

import dpkt
import numpy as np

from canids.types import FeatureExtractor, TrafficType, Packet, TrafficSequence


class BasicPacketFeatureExtractor(FeatureExtractor):
    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        return self._extract_features(traffic, True)

    def map_backwards(
        self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]
    ) -> t.Sequence[TrafficType]:
        return de_result

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        return self._extract_features(traffic, False)

    def _extract_features(
        self, traffic: TrafficSequence, prepare_backwards_mapping: bool
    ):
        feature_matrix = []
        progress = 0
        for packet in traffic.packet_reader:
            feature_matrix.append(self.analyze_packet(packet))
            progress += 1
            if progress % 500_000 == 0:
                logging.info(
                    "Processed %s packets for meta features extraction", progress
                )
        return np.array(feature_matrix)

    def analyze_packet(self, packet: Packet):
        timestamp, buffer = packet
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
        feature_list = (
            [len(eth), src_ip, dest_ip, src_port, dest_port]
            + tcp_features
            + udp_features
        )
        return feature_list

    def get_name(self) -> str:
        return "basic_packet_feature_extractor"

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        pass

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return BasicPacketFeatureExtractor()

    def __str__(self):
        return "BasicPacketFeatureExtractor"
