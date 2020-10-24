import argparse
import logging
import statistics
import typing as t
from enum import Enum

import dpkt
import numpy as np
from tqdm import tqdm

from anomaly_detection.types import FeatureExtractor, TrafficType, Packet, TrafficSequence, Features, FeatureType
from dataset_utils.pcap_utils import get_ip_packet

Protocol = int  # see https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
TCP = Protocol(6)


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


class FeatureSetMode(Enum):
    SUBFLOWS_DETAILED = "subflows_detailed"
    SUBFLOWS_SIMPLE = "subflows_simple"
    WITH_IP = "with_ip"
    TCP = "tcp"


class BasicNetflowFeatureExtractor(FeatureExtractor):

    def __init__(self, flow_timeout: int = 12, subflow_timeout: int = 0.5, verbose: bool = True,
                 modes: t.List[FeatureSetMode] = list()):
        # Stores the mapping "packet index -> flow index" for each traffic sequence name
        self.packets_to_flows: t.Dict[str, t.List[int]] = dict()
        self.flow_timeout = flow_timeout
        self.subflow_timeout = subflow_timeout
        self.verbose = verbose
        self.modes = modes

    def fit_extract(self, traffic: TrafficSequence) -> Features:
        return self.extract_features(traffic)

    def extract_features(self, traffic: TrafficSequence) -> Features:
        flows = self._make_flows(traffic)
        features = self._extract_flow_features(flows)
        return features

    def _make_flows(self, traffic: TrafficSequence) -> t.List[NetFlow]:
        timeout_fn = None
        if FeatureSetMode.TCP in self.modes:
            timeout_fn = tcp_timeout_on_FIN
        netflow_gen = NetFlowGenerator(timeout=self.flow_timeout, timeout_fn=timeout_fn)
        mapping = []
        no_flows_count = 0
        packet_count = 0
        for packet in tqdm(traffic.packet_reader, total=len(traffic.ids), desc="Make netflows",
                           disable=(not self.verbose)):
            flow_index = netflow_gen.feed_packet(packet)
            if flow_index is None:
                no_flows_count += 1
            mapping.append(flow_index)
            packet_count += 1
        netflow_gen.close_all()
        flows = netflow_gen.flows
        self.packets_to_flows[traffic.name] = mapping
        logging.debug(
            "Reduced %s packets to %s flows; %s packets without flow" % (packet_count, len(flows), no_flows_count))
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

    def _extract_flow_features(self, flows: t.List[NetFlow]) -> Features:
        features = []
        names, types = self._make_flow_names_types()
        for f in tqdm(flows, desc="Extract statistical flow features", disable=(not self.verbose)):
            duration = f.duration()
            forward_packets = f.get_packets_in_direction(FlowDirection.FORWARDS)
            backward_packets = f.get_packets_in_direction(FlowDirection.BACKWARDS)
            total = self._extract_packet_list_features(f.packets)
            forward = self._extract_packet_list_features(forward_packets)
            backward = self._extract_packet_list_features(backward_packets)
            features_row = total + forward + backward + [
                duration, f.src_port, f.dest_port, f.protocol]
            if FeatureSetMode.WITH_IP in self.modes:
                features_row += [f.src_ip, f.dest_ip]
            if FeatureSetMode.SUBFLOWS_SIMPLE in self.modes:
                subflows = self._extract_sub_flows_features(f.packets)
                features_row += subflows
            if FeatureSetMode.SUBFLOWS_DETAILED in self.modes:
                subflows_forward = self._extract_sub_flows_features(forward_packets)
                subflows_backward = self._extract_sub_flows_features(backward_packets)
                features_row += subflows_forward + subflows_backward
            if FeatureSetMode.TCP in self.modes:
                features_row += self._make_tcp_features(f, forward_packets, backward_packets)
            features.append(features_row)
        return Features(data=np.array(features), names=names, types=types)

    def _make_tcp_features(self, flow: NetFlow, forward_packets: t.Sequence[Packet],
                           backward_packets: t.Sequence[Packet]):
        if flow.protocol != TCP:
            return 14 * [0]
        features = []
        for pkts in [forward_packets, backward_packets]:
            tcp_packets = [get_ip_packet(buf).data for _, buf in pkts]
            if len(tcp_packets) == 0:
                features += 7 * [0]
                continue
            win_mean = statistics.mean([tcp.win for tcp in tcp_packets])
            total_urg = sum([tcp.flags & dpkt.tcp.TH_URG for tcp in tcp_packets])
            total_syn = sum([tcp.flags & dpkt.tcp.TH_SYN for tcp in tcp_packets])
            total_ack = sum([tcp.flags & dpkt.tcp.TH_ACK for tcp in tcp_packets])
            total_fin = sum([tcp.flags & dpkt.tcp.TH_FIN for tcp in tcp_packets])
            total_push = sum([tcp.flags & dpkt.tcp.TH_PUSH for tcp in tcp_packets])
            total_rst = sum([tcp.flags & dpkt.tcp.TH_RST for tcp in tcp_packets])
            features += [win_mean, total_urg, total_syn, total_ack, total_fin, total_push, total_rst]

        # TODO rtt, syn, synack times
        return features

    def _make_flow_names_types(self):
        def packet_list_features(prefix):
            return map(lambda item: (prefix + "_" + item[0], item[1]), [
                ("sum_pkg_length", FeatureType.INT),
                ("mean_pkg_length", FeatureType.FLOAT),
                ("min_pkg_length", FeatureType.FLOAT),
                ("max_pkg_length", FeatureType.FLOAT),
                ("std_pkg_length", FeatureType.FLOAT),
                ("n_packets", FeatureType.INT),
                ("packets_per_ms", FeatureType.FLOAT),
                ("bytes_per_ms", FeatureType.FLOAT),
                ("avg_ttl", FeatureType.FLOAT)
            ])

        def subflow_features(prefix):
            return map(lambda item: (prefix + "_" + item[0], item[1]), [
                ("n_subflows", FeatureType.INT),
                ("n_active_times", FeatureType.INT),
                ("min_active_time", FeatureType.INT),
                ("max_active_time", FeatureType.INT),
                ("total_active_time", FeatureType.INT),
                ("std_active_time", FeatureType.INT),
                ("mean_active_time", FeatureType.INT),
                ("n_idle_times", FeatureType.INT),
                ("min_idle_time", FeatureType.INT),
                ("max_idle_time", FeatureType.INT),
                ("total_idle_time", FeatureType.INT),
                ("std_idle_time", FeatureType.INT),
                ("mean_idle_time", FeatureType.INT),
            ])

        names_types = [
            *packet_list_features("total"),
            *packet_list_features("forward"),
            *packet_list_features("backward"),
            ("duration", FeatureType.FLOAT),
            ("src_port", FeatureType.INT),
            ("dest_port", FeatureType.INT),
            ("protocol", FeatureType.CATEGORIAL),
        ]
        if FeatureSetMode.WITH_IP in self.modes:
            names_types += [
                ("src_ip", FeatureType.INT),
                ("dest_ip", FeatureType.INT)
            ]
        if FeatureSetMode.SUBFLOWS_SIMPLE in self.modes:
            names_types += [
                *subflow_features("subflows")
            ]
        if FeatureSetMode.SUBFLOWS_DETAILED in self.modes:
            names_types += [
                *subflow_features("subflows_fwd"),
                *subflow_features("subflows_bwd")
            ]
        if FeatureSetMode.TCP in self.modes:
            names_types += [
                ("tcp_fwd_win_mean", FeatureType.FLOAT),
                ("tcp_fwd_total_urg", FeatureType.INT),
                ("tcp_fwd_total_syn", FeatureType.INT),
                ("tcp_fwd_total_ack", FeatureType.INT),
                ("tcp_fwd_total_fin", FeatureType.INT),
                ("tcp_fwd_total_push", FeatureType.INT),
                ("tcp_fwd_total_rst", FeatureType.INT),
                ("tcp_bwd_win_mean", FeatureType.FLOAT),
                ("tcp_bwd_total_urg", FeatureType.INT),
                ("tcp_bwd_total_syn", FeatureType.INT),
                ("tcp_bwd_total_ack", FeatureType.INT),
                ("tcp_bwd_total_fin", FeatureType.INT),
                ("tcp_bwd_total_push", FeatureType.INT),
                ("tcp_bwd_total_rst", FeatureType.INT)
            ]
        return list(zip(*names_types))

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
        # TODO this seems to result in garbage
        # subflow_features = [self._extract_packet_list_features(subflow) for subflow in subflows]
        # by_features = list(zip(*subflow_features))
        # for feature_list in by_features:
        #     if len(feature_list) == 0:
        #         features += [0, 0, 0, 0]
        #     features += [max(feature_list), min(feature_list), statistics.mean(feature_list),
        #                  statistics.pstdev(feature_list)]
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
        ip_stats = self._extract_ip_stats(packet_list)
        if duration == 0:
            packets_per_millisecond = n_packets
            bytes_per_millisecond = length_stats.total
        else:
            packets_per_millisecond = n_packets / duration
            bytes_per_millisecond = length_stats.total / duration
        return [*length_stats] + [n_packets, packets_per_millisecond, bytes_per_millisecond] + ip_stats

    def _extract_ip_stats(self, packet_list: t.List[Packet]):
        if len(packet_list) == 0:
            return [0]
        ttls = []
        for packet in packet_list:
            _, buf = packet
            ip = get_ip_packet(buf)  # TODO refactor with NetFlowGenerator
            if ip is None:
                continue
            ttls.append(ip.ttl)
        if len(ttls) == 0:
            return [0]
        return [sum(ttls) / len(ttls)]

    def get_name(self) -> str:
        return "flow_extractor"

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        parser.add_argument("--flow-timeout", type=float, dest="flow_timeout", default=12_000,
                            help="Flow timeout in milliseconds")
        parser.add_argument("--subflow-timeout", type=float, dest="subflow_timeout", default=500,
                            help="Activity timeout (for subflows) in milliseconds")
        parser.add_argument("--verbose", action="store_true", default=False)
        parser.add_argument("--nf-mode", choices=[m.value for m in FeatureSetMode], nargs="+",
                            help="Feature Selection Modes", default=[])

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return BasicNetflowFeatureExtractor(
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
            verbose=args.verbose,
            modes=[FeatureSetMode(v) for v in args.nf_mode]
        )

    def __str__(self):
        return self.get_id()

    def get_id(self) -> str:
        modes = sorted([m.value for m in self.modes])
        id_parts = [self.get_name(), "timeout=" + str(self.flow_timeout)]
        if FeatureSetMode.SUBFLOWS_SIMPLE in self.modes or FeatureSetMode.SUBFLOWS_DETAILED in self.modes:
            # information about subflows must only be displayed if subflows are actually used
            sf_part = f", sf_timeout={self.subflow_timeout}"
        else:
            sf_part = ""
        return f"FlowExtractor(timeout={self.flow_timeout}, modes={modes}{sf_part})"


def tcp_timeout_on_FIN(packet: Packet, flow: NetFlow):
    if flow.protocol != TCP:
        return None
    ts, buf = packet
    tcp = get_ip_packet(buf).data
    if type(tcp) is not dpkt.tcp.TCP:
        return None
    return tcp.flags & dpkt.tcp.TH_FIN != 0


class NetFlowGenerator:
    def __init__(self, timeout: int = 10_000, timeout_fn=None):
        self.flows: t.List[NetFlow] = list()
        self.open_flows: t.Dict[FlowIdentifier, int] = dict()
        self.timeout = timeout  # milliseconds
        self.timeout_fn = timeout_fn

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
            if self.is_timeout(packet, flow):
                self.close_flow(flow_id)
                flow_index = self.open_flow(packet, flow_id, packet_infos)
            else:
                flow_direction = self.get_packet_direction(packet_infos, flow_id)
                flow.add_packet(packet, flow_direction)
        return flow_index

    def is_timeout(self, packet, flow):
        if self.timeout_fn is None:
            timestamp, _ = packet
            return timestamp - flow.end_time() > self.timeout
        is_timeout = self.timeout_fn(packet, flow)
        if is_timeout is None:
            timestamp, _ = packet
            return timestamp - flow.end_time() > self.timeout
        return is_timeout

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
        ip = get_ip_packet(buf)
        if ip is None:
            return None
        src_ip = int.from_bytes(ip.src, "big")
        dest_ip = int.from_bytes(ip.dst, "big")
        protocol = ip.p
        src_port = get_if_exists(ip.data, key="sport", default=0)
        dest_port = get_if_exists(ip.data, key="dport", default=0)
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


def get_if_exists(obj, key, default):
    if hasattr(obj, key):
        return obj[key]
    else:
        return default
