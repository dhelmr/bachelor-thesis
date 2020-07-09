import argparse
import statistics
import typing as t
from enum import Enum

import dpkt
import numpy as np
from tqdm import tqdm

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


class FlowDirection(Enum):
    FORWARDS = 0
    BACKWARDS = 1


class NetFlow(t.NamedTuple):
    src_ip: int
    dest_ip: int
    src_port: int
    dest_port: int
    protocol: Protocol
    start_time: float
    packets: t.List[Packet]
    forward_packets_indexes: t.List[int]
    backward_packets_indexes: t.List[int]

    def end_time(self):
        return self.packets[-1][0]

    def duration(self):
        return self.end_time() - self.start_time

    def add_packet(self, packet: Packet, direction: FlowDirection):
        self.packets.append(packet)
        index = len(self.packets) - 1
        if direction == FlowDirection.BACKWARDS:
            self.backward_packets_indexes.append(index)
        elif direction == FlowDirection.FORWARDS:
            self.forward_packets_indexes.append(index)

    def get_packets_in_direction(self, direction: FlowDirection) -> t.List[Packet]:
        if direction == FlowDirection.FORWARDS:
            return [self.packets[i] for i in self.forward_packets_indexes]
        if direction == FlowDirection.BACKWARDS:
            return [self.packets[i] for i in self.backward_packets_indexes]


class PacketLengthStats(t.NamedTuple):
    total: int
    mean: float
    min: int
    max: int
    std: float


def packet_length_stats(packets: t.List[Packet]) -> PacketLengthStats:
    lengths = [len(buf) for ts, buf in packets]
    if len(packets) == 0:
        return PacketLengthStats(
            0, 0, 0, 0, 0
        )
    return PacketLengthStats(
        total=sum(lengths),
        mean=statistics.mean(lengths),
        min=min(lengths),
        max=max(lengths),
        std=statistics.pstdev(lengths)
    )


class BasicNetflowFeatureExtractor(FeatureExtractor):

    def __init__(self, flow_timeout: int, subflow_timeout: int = 10):
        # Stores the mapping "packet index -> flow index" for each traffic sequence name
        self.packets_to_flows: t.Dict[str, t.List[int]] = dict()
        self.flow_timeout = flow_timeout
        self.subflow_timeout = subflow_timeout

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        return self.extract_features(traffic)

    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        flows = self._make_flows(traffic)
        features = self._extract_flow_features(flows)
        return features

    def _make_flows(self, traffic: TrafficSequence) -> t.List[NetFlow]:
        netflow_gen = NetFlowGenerator()
        mapping = []
        for packet in tqdm(traffic.packet_reader, total=len(traffic.ids), desc="Make netflows"):
            flow_index = netflow_gen.feed_packet(packet)
            mapping.append(flow_index)
        netflow_gen.close_all()
        flows = netflow_gen.flows
        self.packets_to_flows[traffic.name] = mapping
        return flows

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
        for f in tqdm(flows, desc="Extract statistical flow features"):
            duration = f.duration()
            forward_packets = f.get_packets_in_direction(FlowDirection.FORWARDS)
            backward_packets = f.get_packets_in_direction(FlowDirection.BACKWARDS)
            total = self._extract_packet_list_features(f.packets)
            forward = self._extract_packet_list_features(forward_packets)
            backward = self._extract_packet_list_features(backward_packets)
            subflows = self._extract_sub_flows_features(f.packets)
            subflows_forward = self._extract_sub_flows_features(forward_packets)
            subflows_backward = self._extract_sub_flows_features(backward_packets)
            features_row = total + forward + backward + subflows + subflows_forward + subflows_backward + [
                duration, f.src_ip, f.dest_ip, f.src_port, f.dest_port, f.protocol.value]
            features.append(features_row)
        return np.array(features)

    def _extract_sub_flows_features(self, flow: t.List[Packet]):
        subflows = self._make_subflows(flow)
        features = [len(subflows)]
        active_times = []
        idle_times = []
        last_active_ts = -1
        for subflow in subflows:
            if len(subflow) == 0:
                continue
            first_ts, _ = subflow[0]
            last_ts, _ = subflow[-1]
            if last_active_ts != -1:
                idle_time = first_ts - last_active_ts
                idle_times.append(idle_time)
            active_times.append(last_ts - first_ts)
            last_active_ts = last_ts
        for time_list in [active_times, idle_times]:
            if len(time_list) == 0:
                features += [0, 0, 0, 0, 0, 0]
                continue
            features += [len(time_list), min(time_list), max(time_list), sum(time_list), statistics.pstdev(time_list),
                         statistics.mean(time_list)]
        subflow_features = [self._extract_packet_list_features(subflow) for subflow in subflows]
        by_features = list(zip(*subflow_features))
        for feature_list in by_features:
            if len(feature_list) == 0:
                features += [0, 0, 0, 0]
            features += [max(feature_list), min(feature_list), statistics.mean(feature_list),
                         statistics.pstdev(feature_list)]
        return features

    def _make_subflows(self, flow: t.List[Packet]) -> t.List[t.List[Packet]]:
        sub_flows = []
        current_sub_flow = []
        for packet in flow:
            ts, buf = packet
            if len(current_sub_flow) == 0:
                current_sub_flow.append(packet)
                continue
            last_ts, _ = current_sub_flow[-1]
            if ts - last_ts > self.subflow_timeout:
                sub_flows.append(current_sub_flow)
                current_sub_flow = [packet]
                continue
            current_sub_flow.append(packet)
        sub_flows.append(current_sub_flow)
        return sub_flows

    def _extract_packet_list_features(self, packet_list: t.List[Packet]):
        if len(packet_list) == 0:
            duration = 0
        else:
            duration = packet_list[-1][0] - packet_list[0][0]
        n_packets = len(packet_list)
        length_stats = packet_length_stats(packet_list)
        if duration == 0:
            packets_per_millisecond = n_packets
            bytes_per_millisecond = length_stats.total
        else:
            packets_per_millisecond = n_packets / duration
            bytes_per_millisecond = length_stats.total / duration
        return [*length_stats] + [n_packets, packets_per_millisecond, bytes_per_millisecond]

    def get_name(self) -> str:
        return "basic_netflow_extractor"

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        parser.add_argument("--flow-timeout", type=float, dest="flow_timeout", default=12_000,
                            help="Flow timeout in milliseconds")
        parser.add_argument("--subflow-timeout", type=float, dest="subflow_timeout", default=500,
                            help="Activity timeout (for subflows) in milliseconds")

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return BasicNetflowFeatureExtractor(flow_timeout=args.flow_timeout, subflow_timeout=args.subflow_timeout)

    def __str__(self):
        return f"BasicNetflowFeatureExtractor"


class NetFlowGenerator:
    def __init__(self, timeout: int = 10_000):
        self.flows: t.List[NetFlow] = list()
        self.open_flows: t.Dict[FlowIdentifier, int] = dict()
        self.timeout = timeout  # milliseconds

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
                flow_direction = self.get_packet_direction(packet_infos, flow_id)
                flow.add_packet(packet, flow_direction)
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
            packets=[],
            forward_packets_indexes=[],
            backward_packets_indexes=[]
        )
        flow.add_packet(packet, FlowDirection.FORWARDS)
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

    def get_packet_direction(self, packet_info: t.Tuple, flow_id: FlowIdentifier) -> FlowDirection:
        if packet_info[0] == flow_id[0]:
            return FlowDirection.FORWARDS
        else:
            return FlowDirection.BACKWARDS
