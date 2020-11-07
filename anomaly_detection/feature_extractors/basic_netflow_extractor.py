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
UDP = Protocol(17)

IPPacket = t.Tuple[float, dpkt.ip.IP]


class FlowIdentifier(t.NamedTuple):
    """
    Used for identifying a bi-directional IP-based network flow
    """
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
    packets: t.List[IPPacket]
    forward_packets_indexes: t.List[int]
    backward_packets_indexes: t.List[int]

    def end_time(self):
        return self.packets[-1][0]

    def duration(self):
        return self.end_time() - self.start_time

    def add_packet(self, packet: IPPacket, direction: FlowDirection):
        self.packets.append(packet)
        index = len(self.packets) - 1
        if direction == FlowDirection.BACKWARDS:
            self.backward_packets_indexes.append(index)
        elif direction == FlowDirection.FORWARDS:
            self.forward_packets_indexes.append(index)

    def get_packets_in_direction(self, direction: FlowDirection) -> t.List[IPPacket]:
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


class FeatureSetMode(Enum):
    SUBFLOWS_DETAILED = "subflows_detailed"
    SUBFLOWS_SIMPLE = "subflows_simple"
    WITH_IP_ADDR = "with_ip_addr"
    TCP = "tcp"
    INCLUDE_HEADER_LENGTH = "include_header_length"
    HINDSIGHT = "hindsight"
    # the following features are only useful with a OnehotEncoder
    IP_CATEGORIAL = "ip_categorial"
    PORT_CATEGORIAL = "port_categorial"


NOT_APPLICABLE_FEATURE_VALUE = -1


class BasicNetflowFeatureExtractor(FeatureExtractor):

    def __init__(self, flow_timeout: int = 12, subflow_timeout: int = 0.5, verbose: bool = True,
                 modes: t.List[FeatureSetMode] = list()):
        # Stores the mapping "packet index -> flow index" for each traffic sequence name
        self.packets_to_flows: t.Dict[str, t.List[int]] = dict()
        self.flow_timeout = flow_timeout
        self.subflow_timeout = subflow_timeout
        self.verbose = verbose
        self.modes = modes
        self.hindsight_window = 100
        self.validate()

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
        for i, f in enumerate(tqdm(flows, desc="Extract statistical flow features", disable=(not self.verbose))):
            forward_packets = f.get_packets_in_direction(FlowDirection.FORWARDS)
            backward_packets = f.get_packets_in_direction(FlowDirection.BACKWARDS)
            total = self._extract_packet_list_features(f.packets)
            forward = self._extract_packet_list_features(forward_packets)
            backward = self._extract_packet_list_features(backward_packets)
            features_row = [f.src_port, f.dest_port, f.protocol] + total + forward + backward
            if FeatureSetMode.WITH_IP_ADDR in self.modes:
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
            if FeatureSetMode.HINDSIGHT in self.modes:
                last_flows = flows[max(0, i - self.hindsight_window):i]
                features_row += self._make_hindsight_features(f, last_flows)
            features.append(features_row)
        return Features(data=np.array(features), names=names, types=types)

    def _make_tcp_features(self, flow: NetFlow, forward_packets: t.Sequence[IPPacket],
                           backward_packets: t.Sequence[IPPacket]):
        if flow.protocol != TCP:
            return 14 * [NOT_APPLICABLE_FEATURE_VALUE]
        features = []
        for pkts in [forward_packets, backward_packets]:
            tcp_packets = [ip_packet.data for _, ip_packet in pkts]
            if len(tcp_packets) == 0:
                features += 7 * [NOT_APPLICABLE_FEATURE_VALUE]
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

    def _make_hindsight_features(self, flow: NetFlow, last_flows: t.List[NetFlow]):
        dest_addr_src_port = 0
        src_addr_dest_port = 0
        src_addr = 0
        dest_addr = 0
        dest_addr_prot = 0
        src_addr_port = 0
        for last_flow in last_flows:
            if last_flow.protocol == flow.protocol and last_flow.src_ip == flow.src_ip:
                src_addr_port += 1
            if last_flow.protocol == flow.protocol and last_flow.dest_ip == flow.dest_ip:
                dest_addr_prot += 1
            if last_flow.dest_ip == flow.dest_ip:
                dest_addr += 1
            if last_flow.src_ip == flow.src_ip:
                src_addr += 1
            if last_flow.src_ip == flow.src_ip and last_flow.dest_port == flow.dest_port:
                src_addr_dest_port += 1
            if last_flow.dest_ip == flow.dest_ip and last_flow.src_port == flow.src_port:
                dest_addr_src_port += 1
        return [dest_addr_src_port, src_addr_dest_port, src_addr, dest_addr, dest_addr_prot, src_addr_port]

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
                ("avg_ttl", FeatureType.FLOAT),
                ("iat_std", FeatureType.FLOAT),
                ("iat_min", FeatureType.FLOAT),
                ("iat_max", FeatureType.FLOAT),
                ("iat_sum", FeatureType.FLOAT)
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
            ("src_port", FeatureType.CATEGORIAL if FeatureSetMode.PORT_CATEGORIAL in self.modes else FeatureType.INT),
            ("dest_port", FeatureType.CATEGORIAL if FeatureSetMode.PORT_CATEGORIAL in self.modes else FeatureType.INT),
            ("protocol", FeatureType.CATEGORIAL),
            *packet_list_features("total"),
            *packet_list_features("forward"),
            *packet_list_features("backward"),
        ]
        if FeatureSetMode.WITH_IP_ADDR in self.modes:
            names_types += [
                ("src_ip", FeatureType.CATEGORIAL if FeatureSetMode.PORT_CATEGORIAL in self.modes else FeatureType.INT),
                ("dest_ip", FeatureType.CATEGORIAL if FeatureSetMode.PORT_CATEGORIAL in self.modes else FeatureType.INT)
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
        if FeatureSetMode.HINDSIGHT in self.modes:
            names_types += [
                ("hindsight_dest_addr_src_port", FeatureType.INT),
                ("hindsight_src_addr_dest_port", FeatureType.INT),
                ("hindsight_src_addr", FeatureType.INT),
                ("hindsight_dest_addr", FeatureType.INT),
                ("hindsight_dest_addr_prot", FeatureType.INT),
                ("hindsight_src_addr_port", FeatureType.INT)
            ]
        names, types = zip(*names_types)
        return list(names), list(types)

    def _extract_sub_flows_features(self, flow: t.List[IPPacket]):
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

    def _make_subflows(self, flow: t.List[IPPacket]) -> t.List[t.List[IPPacket]]:
        sub_flows = []
        current_sub_flow = []
        for packet in flow:
            ts, ip = packet
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

    def _extract_packet_list_features(self, packet_list: t.List[IPPacket]):
        if len(packet_list) == 0:
            duration = 0
        else:
            duration = packet_list[-1][0] - packet_list[0][0]
        n_packets = len(packet_list)
        length_stats = self.packet_length_stats(packet_list)
        ip_stats = self._extract_ip_stats(packet_list)
        time_stats = self._extract_time_features(packet_list)
        if duration == 0:
            packets_per_millisecond = n_packets
            bytes_per_millisecond = length_stats.total
        else:
            packets_per_millisecond = n_packets / duration
            bytes_per_millisecond = length_stats.total / duration
        return [*length_stats] + [n_packets, packets_per_millisecond, bytes_per_millisecond] + ip_stats + time_stats

    def _extract_ip_stats(self, packet_list: t.List[IPPacket]):
        if len(packet_list) == 0:
            return [NOT_APPLICABLE_FEATURE_VALUE]
        ttls = []
        for packet in packet_list:
            _, ip = packet
            if ip is None:
                continue
            ttls.append(ip.ttl)
        if len(ttls) == 0:
            return [NOT_APPLICABLE_FEATURE_VALUE]
        return [sum(ttls) / len(ttls)]

    def _extract_time_features(self, packet_list: t.List[IPPacket]):
        if len(packet_list) <= 1:
            # inter_arrival_times cannot be calculated if there is only on packet
            return [NOT_APPLICABLE_FEATURE_VALUE] * 4
        inter_arrival_times = []
        last_ts = packet_list[0][0]
        for ts, packet in packet_list[1:]:
            inter_arrival_times.append(ts - last_ts)
            last_ts = ts
        return [statistics.pstdev(inter_arrival_times),
                min(inter_arrival_times), max(inter_arrival_times), sum(inter_arrival_times)]

    @staticmethod
    def get_name() -> str:
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

    def get_db_params_dict(self):
        params = {
            "flow_timeout": self.flow_timeout,
            "subflow_timeout": self.subflow_timeout
        }
        for nf_mode in FeatureSetMode:
            params[nf_mode.name] = nf_mode in self.modes
        return params

    def packet_length_stats(self, packets: t.List[IPPacket]) -> PacketLengthStats:
        if FeatureSetMode.INCLUDE_HEADER_LENGTH in self.modes:
            lengths = [len(ip) for _, ip in packets]
        else:
            # by default, only the IP packet's payload is taken into account
            lengths = [len(ip.data) for _, ip in packets]
        if len(packets) == 0:
            return PacketLengthStats(
                *[NOT_APPLICABLE_FEATURE_VALUE] * 5
            )
        return PacketLengthStats(
            total=sum(lengths),
            mean=statistics.mean(lengths),
            min=min(lengths),
            max=max(lengths),
            std=statistics.pstdev(lengths)
        )

    def validate(self):
        if FeatureSetMode.IP_CATEGORIAL in self.modes and FeatureSetMode.WITH_IP_ADDR not in self.modes:
            raise ValueError(
                f"'{FeatureSetMode.IP_CATEGORIAL.value}' can only be set as a netflow mode if '{FeatureSetMode.WITH_IP_ADDR.value}' is set as well.")


def tcp_timeout_on_FIN(packet: IPPacket, flow: NetFlow):
    """
    Is used for determining when a TCP flow ends. A TCP flow is closed when a FIN packet is observed, even
    if the timeout is not yet exceeded.
    """
    if flow.protocol != TCP:
        return None
    ts, ip = packet
    tcp = ip.data
    if type(tcp) is not dpkt.tcp.TCP:
        return None
    return tcp.flags & dpkt.tcp.TH_FIN != 0


class NetFlowGenerator:
    def __init__(self, timeout: int = 10_000, timeout_fn: t.Optional[t.Callable[[IPPacket], bool]] = None):
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
        ip_packet = (timestamp, packet_infos[0])
        if flow_id not in self.open_flows:
            flow_index = self.open_flow(ip_packet, flow_id, packet_infos)
        else:
            flow_index = self.open_flows[flow_id]
            flow = self.flows[flow_index]
            if self.is_timeout(ip_packet, flow):
                self.close_flow(flow_id)
                flow_index = self.open_flow(ip_packet, flow_id, packet_infos)
            else:
                flow_direction = self.get_packet_direction(packet_infos, flow_id)
                flow.add_packet(ip_packet, flow_direction)
        return flow_index

    def is_timeout(self, packet: IPPacket, flow):
        if self.timeout_fn is None:
            timestamp, _ = packet
            return timestamp - flow.end_time() > self.timeout
        is_timeout = self.timeout_fn(packet, flow)
        if is_timeout is None:
            timestamp, _ = packet
            return timestamp - flow.end_time() > self.timeout
        return is_timeout

    def open_flow(self, packet: IPPacket, flow_id: FlowIdentifier, packet_infos: t.Tuple) -> int:
        ts, _ = packet
        flow = NetFlow(
            src_ip=packet_infos[1],
            dest_ip=packet_infos[2],
            src_port=packet_infos[3],
            dest_port=packet_infos[4],
            protocol=packet_infos[5],
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
        return ip, src_ip, dest_ip, src_port, dest_port, protocol

    def make_flow_id(self, ip_packet, src_ip, dest_ip, src_port, dest_port, protocol) -> FlowIdentifier:
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
