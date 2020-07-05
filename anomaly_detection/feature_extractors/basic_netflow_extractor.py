import statistics
import typing as t
from enum import Enum

import dpkt
import numpy as np

from anomaly_detection.types import FeatureExtractor, TrafficType, Packet, TrafficSequence


class Protocol(Enum):
    TCP = 0
    UDP = 1
    OTHER = 2


class FlowIdentifier(t.NamedTuple):
    ip_a: int
    ip_b: int
    port_a: int
    port_b: int
    protocol: Protocol


class NetFlow(t.NamedTuple):
    src_ip: int
    dest_ip: int
    src_port: int
    dest_port: int
    protocol: Protocol
    start_time: float
    packets: t.List[Packet]

    def end_time(self):
        return self.packets[-1][0]

    def duration(self):
        return self.end_time() - self.start_time


class PacketLengthStats(t.NamedTuple):
    total: int
    mean: float
    min: int
    max: int
    std: float


def packet_length_stats(packets: t.List[Packet]) -> PacketLengthStats:
    lengths = [len(buf) for ts, buf in packets]
    return PacketLengthStats(
        total=sum(lengths),
        mean=statistics.mean(lengths),
        min=min(lengths),
        max=max(lengths),
        std=statistics.pstdev(lengths)
    )


class BasicNetflowFeatureExtractor(FeatureExtractor):
    def __init__(self):
        self.packets_to_flows: t.Dict[
            str, t.List[int]] = dict()  # Stores the mapping "packet index -> flow index" for each traffic sequence name

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        # there is no need to do anything here, the features will be extracted statically for each netflow,
        # i.e. disregarding the other traffic records
        return self.extract_features(traffic)

    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        netflow_gen = NetFlowGenerator()
        mapping = []
        for packet in traffic.packet_reader:
            flow_index = netflow_gen.feed_packet(packet)
            mapping.append(flow_index)
        netflow_gen.close_all()
        self.packets_to_flows[traffic.name] = mapping
        features = self._extract_flow_features(netflow_gen.flows)
        return features

    def map_backwards(self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        if traffic.name not in self.packets_to_flows:
            raise ValueError("No flow <-> packet mapping for %s available" % traffic.name)
        mapping = self.packets_to_flows[traffic.name]
        packet_classifications = []
        for flow_index in mapping:
            if flow_index is None:
                packet_classifications.append(TrafficType.BENIGN)
            else:
                packet_classifications.append(de_result[flow_index])
        return packet_classifications


    def _extract_flow_features(self, flows: t.List[NetFlow]) -> np.ndarray:
        features = []
        for f in flows:
            n_packets = len(f.packets)
            duration = f.duration()
            length_stats = packet_length_stats(f.packets)
            if duration == 0:
                packets_per_millisecond = n_packets
                bytes_per_millisecond = length_stats.total
            else:
                packets_per_millisecond = n_packets / duration
                bytes_per_millisecond = length_stats.total / duration
            features_row = [*length_stats] + [n_packets, duration, packets_per_millisecond, bytes_per_millisecond,
                                              f.src_ip, f.dest_ip, f.src_port, f.dest_port, f.protocol.value]
            features.append(features_row)
        return np.array(features)

    def get_name(self) -> str:
        return "basic_netflow_extractor"


class NetFlowGenerator:
    def __init__(self):
        self.flows: t.List[NetFlow] = list()
        self.open_flows: t.Dict[FlowIdentifier, int] = dict()
        self.timeout = 10_000  # milliseconds

    def feed_packet(self, packet: Packet) -> t.Optional[int]:
        timestamp, buf = packet
        packet_infos = self.read_packet_infos(packet)
        if packet_infos is None:
            return None
        flow_id = self.make_flow_id(*packet_infos)
        if flow_id not in self.open_flows:
            flow_index = self.open_flow(packet, flow_id, packet_infos)
        else:
            flow_index = self.open_flows[flow_id]
            flow = self.flows[flow_index]
            if timestamp - flow.end_time() > self.timeout:
                self.close_flow(flow_id)
                flow_index = self.open_flow(packet, flow_id, packet_infos)
            else:
                flow.packets.append(packet)
        return flow_index

    def open_flow(self, packet: Packet, flow_id: FlowIdentifier, packet_infos: t.Tuple) -> int:
        ts, _ = packet
        flow = NetFlow(
            src_ip=packet_infos[0],
            dest_ip=packet_infos[1],
            src_port=packet_infos[2],
            dest_port=packet_infos[3],
            protocol=packet_infos[4],
            start_time=ts,
            packets=[packet]
        )
        self.flows.append(flow)
        index = len(self.flows) - 1
        self.open_flows[flow_id] = index
        return index

    def close_flow(self, flow_id: FlowIdentifier):
        del self.open_flows[flow_id]

    def close_all(self):
        items = list(self.open_flows.items())
        for flow_id, flow in items:
            self.close_flow(flow_id)

    def read_packet_infos(self, packet: Packet) -> t.Optional[t.Tuple]:
        ts, buf = packet
        eth = dpkt.ethernet.Ethernet(buf)
        if type(eth.data) is not dpkt.ip.IP:
            return None
        src_ip = int.from_bytes(eth.ip.src, "big")
        dest_ip = int.from_bytes(eth.ip.dst, "big")
        if type(eth.ip.data) is dpkt.tcp.TCP:
            src_port = int(eth.ip.tcp.sport)
            dest_port = int(eth.ip.tcp.dport)
            protocol = Protocol.TCP
        elif type(eth.ip.data) is dpkt.udp.UDP:
            src_port = int(eth.ip.udp.sport)
            dest_port = int(eth.ip.udp.dport)
            protocol = Protocol.UDP
        else:
            src_port = 0
            dest_port = 0
            protocol = Protocol.OTHER  # TODO differentiate more protocols
        return src_ip, dest_ip, src_port, dest_port, protocol

    def make_flow_id(self, src_ip, dest_ip, src_port, dest_port, protocol) -> FlowIdentifier:
        if src_ip < dest_ip:
            ip_a = src_ip
            ip_b = dest_ip
            port_a = src_port
            port_b = dest_port
        else:
            ip_a = dest_ip
            ip_b = src_ip
            port_a = dest_port
            port_b = src_port
        return FlowIdentifier(ip_a, ip_b, port_a, port_b, protocol)
