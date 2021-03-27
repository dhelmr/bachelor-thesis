import argparse
import logging
import socket
import statistics
import typing as t
from enum import Enum

import dpkt
import numpy as np
from tqdm import tqdm

from canids.dataset_utils.pcap_utils import get_ip_packet
from canids.types import (
    FeatureExtractor,
    TrafficType,
    Packet,
    TrafficSequence,
    Features,
    FeatureType,
)

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
    SUBFLOWS = "subflows"
    WITH_IP_ADDR = "with_ip_addr"
    TCP = "tcp"
    INCLUDE_HEADER_LENGTH = "include_header_length"
    HINDSIGHT = "hindsight"
    # the following features are only useful with a OnehotEncoder
    IP_DOTTED = "ip_dotted"
    PORT_DECIMAL = "port_decimal"
    BASIC = "basic"
    TCP_END_ON_RST = "tcp_end_on_rst"


NOT_APPLICABLE_FEATURE_VALUE = -1


class BasicNetflowFeatureExtractor(FeatureExtractor):
    def __init__(
        self,
        flow_timeout: int = 12,
        subflow_timeout: int = 0.5,
        hindsight_window: int = 100,
        verbose: bool = True,
        modes=None,
    ):
        if modes is None:
            modes = list()
        # Stores the mapping "packet index -> flow index" for each traffic sequence name
        self.packets_to_flows: t.Dict[str, t.List[int]] = dict()
        self.flow_timeout = flow_timeout
        self.subflow_timeout = subflow_timeout
        self.verbose = verbose
        self.modes = modes
        self.hindsight_window = hindsight_window
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
            end_on_rst = FeatureSetMode.TCP_END_ON_RST in self.modes
            timeout_fn = lambda pkt, flow: tcp_timeout_on_FIN(pkt, flow, end_on_rst)
        netflow_gen = NetFlowGenerator(timeout=self.flow_timeout, timeout_fn=timeout_fn)
        mapping = []
        no_flows_count = 0
        packet_count = 0
        for packet in tqdm(
            traffic.packet_reader,
            total=len(traffic.ids),
            desc="Make netflows",
            disable=(not self.verbose),
        ):
            flow_index = netflow_gen.feed_packet(packet)
            if flow_index is None:
                no_flows_count += 1
            mapping.append(flow_index)
            packet_count += 1
        netflow_gen.close_all()
        flows = netflow_gen.flows
        self.packets_to_flows[traffic.name] = mapping
        logging.debug(
            "Reduced %s packets to %s flows; %s packets without flow"
            % (packet_count, len(flows), no_flows_count)
        )
        return flows

    def map_backwards(
        self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]
    ) -> t.Sequence[TrafficType]:
        if traffic.name not in self.packets_to_flows:
            raise ValueError(
                "No flow <-> packet mapping for %s available" % traffic.name
            )
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
        for i, f in enumerate(
            tqdm(
                flows,
                desc="Extract statistical flow features",
                disable=(not self.verbose),
            )
        ):
            if FeatureSetMode.BASIC in self.modes:
                features.append([f.src_port, f.dest_port, f.protocol])
                continue
            forward_packets = f.get_packets_in_direction(FlowDirection.FORWARDS)
            backward_packets = f.get_packets_in_direction(FlowDirection.BACKWARDS)
            total = self._extract_packet_list_features(f.packets)
            forward = self._extract_packet_list_features(forward_packets)
            backward = self._extract_packet_list_features(backward_packets)
            features_row = (
                self._get_port_features(f.src_port)
                + self._get_port_features(f.dest_port)
                + [f.protocol]
                + total
                + forward
                + backward
            )
            if FeatureSetMode.WITH_IP_ADDR in self.modes:
                src_features = self._get_ip_addr_features(f.src_ip)
                dest_features = self._get_ip_addr_features(f.dest_ip)
                features_row += src_features + dest_features
            if FeatureSetMode.SUBFLOWS in self.modes:
                active_idle_features = self._extract_active_idle_features(f.packets)
                subflows_forward = self._extract_subflow_features(forward_packets)
                subflows_backward = self._extract_subflow_features(backward_packets)
                features_row += (
                    active_idle_features + subflows_forward + subflows_backward
                )
            if FeatureSetMode.TCP in self.modes:
                features_row += self._make_tcp_features(
                    f, forward_packets, backward_packets
                )
            if FeatureSetMode.HINDSIGHT in self.modes:
                window_start = int(max(0, i - self.hindsight_window))
                last_flows = flows[window_start:i]
                features_row += self._make_hindsight_features(f, last_flows)
            features.append(features_row)
        return Features(data=np.array(features), names=names, types=types)

    def _get_port_features(self, port: int):
        if FeatureSetMode.PORT_DECIMAL in self.modes:
            features = [port // 10 ** n % 10 for n in range(8)]
            return features
        else:
            return [port]

    def _get_ip_addr_features(self, ip: int):
        if FeatureSetMode.IP_DOTTED in self.modes:
            # convert to 6 bytes (IPv6 compatible)
            as_bytes = ip.to_bytes(length=16, byteorder="big")
            # dotted = socket.inet_ntoa(as_bytes)
            dotted = socket.inet_ntop(socket.AF_INET6, as_bytes)
            dotted_features = [
                int(part)
                for part in dotted.replace("::", ".").split(".")
                if part.strip() != ""
            ]
            if len(dotted_features) == 4:
                return [NOT_APPLICABLE_FEATURE_VALUE] * 12 + dotted_features
            elif len(dotted_features) != 16:
                logging.warning(
                    "Something went wrong with creating dotted ip representation: %s",
                    dotted_features,
                )
                return [NOT_APPLICABLE_FEATURE_VALUE] * 16
            return dotted_features
        else:
            return [ip]

    def _make_tcp_features(
        self,
        flow: NetFlow,
        forward_packets: t.Sequence[IPPacket],
        backward_packets: t.Sequence[IPPacket],
    ):
        if flow.protocol != TCP:
            return 19 * [NOT_APPLICABLE_FEATURE_VALUE]
        features = []
        for pkts in [forward_packets, backward_packets]:
            tcp_packets = [ip_packet.data for _, ip_packet in pkts]
            if len(tcp_packets) == 0:
                features += 8 * [NOT_APPLICABLE_FEATURE_VALUE]
                continue
            win_mean = statistics.mean([tcp.win for tcp in tcp_packets])
            total_urg = sum(
                [1 if tcp.flags & dpkt.tcp.TH_URG != 0 else 0 for tcp in tcp_packets]
            )
            total_syn = sum([1 if is_tcp_syn(tcp) else 0 for tcp in tcp_packets])
            total_syn_ack = sum(
                [1 if is_tcp_syn_ack(tcp) else 0 for tcp in tcp_packets]
            )
            total_ack = sum([1 if is_tcp_ack(tcp) else 0 for tcp in tcp_packets])
            total_fin = sum(
                [1 if tcp.flags & dpkt.tcp.TH_FIN != 0 else 0 for tcp in tcp_packets]
            )
            total_push = sum(
                [1 if tcp.flags & dpkt.tcp.TH_PUSH != 0 else 0 for tcp in tcp_packets]
            )
            total_rst = sum(
                [1 if tcp.flags & dpkt.tcp.TH_RST != 0 else 0 for tcp in tcp_packets]
            )
            features += [
                win_mean,
                total_urg,
                total_syn,
                total_syn_ack,
                total_ack,
                total_fin,
                total_push,
                total_rst,
            ]

        ts_syn = -1
        ts_syn_ack = -1
        ts_ack = -1
        syn_from = None
        for ts, ip_packet in flow.packets:
            tcp = ip_packet.data
            if is_tcp_syn(tcp) and ts_syn == -1:
                ts_syn = ts
                syn_from = (ip_packet.src, tcp.sport)
            if (
                is_tcp_syn_ack(tcp)
                and ts_syn != -1
                and ts_syn_ack == -1
                and (ip_packet.dst, tcp.dport) == syn_from
            ):
                ts_syn_ack = ts
            if (
                is_tcp_ack(tcp)
                and ts_syn != -1
                and ts_syn_ack != -1
                and ts_ack == -1
                and (ip_packet.src, tcp.sport) == syn_from
            ):
                ts_ack = ts
                break
        features += [
            (ts_syn_ack - ts_syn)
            if ts_syn != -1 and ts_ack != -1
            else NOT_APPLICABLE_FEATURE_VALUE,
            (ts_ack - ts_syn_ack)
            if ts_ack != -1 and ts_ack != -1
            else NOT_APPLICABLE_FEATURE_VALUE,
            (ts_ack - ts_syn)
            if ts_ack != -1 and ts_syn != -1
            else NOT_APPLICABLE_FEATURE_VALUE,
        ]

        return features

    def _make_hindsight_features(self, flow: NetFlow, last_flows: t.List[NetFlow]):
        dest_addr_src_port = 0
        src_addr_dest_port = 0
        src_addr = 0
        dest_addr = 0
        dest_addr_prot = 0
        src_addr_prot = 0
        for last_flow in last_flows:
            if last_flow.protocol == flow.protocol and last_flow.src_ip == flow.src_ip:
                src_addr_prot += 1
            if (
                last_flow.protocol == flow.protocol
                and last_flow.dest_ip == flow.dest_ip
            ):
                dest_addr_prot += 1
            if last_flow.dest_ip == flow.dest_ip:
                dest_addr += 1
            if last_flow.src_ip == flow.src_ip:
                src_addr += 1
            if (
                last_flow.src_ip == flow.src_ip
                and last_flow.dest_port == flow.dest_port
            ):
                src_addr_dest_port += 1
            if (
                last_flow.dest_ip == flow.dest_ip
                and last_flow.src_port == flow.src_port
            ):
                dest_addr_src_port += 1
        return [
            dest_addr_src_port,
            src_addr_dest_port,
            src_addr,
            dest_addr,
            dest_addr_prot,
            src_addr_prot,
        ]

    def _make_flow_names_types(self):
        def packet_list_features(prefix):
            return map(
                lambda item: (prefix + "_" + item[0], item[1]),
                [
                    ("sum_pkt_length", FeatureType.INT),
                    ("mean_pkt_length", FeatureType.FLOAT),
                    ("min_pkt_length", FeatureType.FLOAT),
                    ("max_pkt_length", FeatureType.FLOAT),
                    ("std_pkt_length", FeatureType.FLOAT),
                    ("n_packets", FeatureType.INT),
                    ("packets_per_s", FeatureType.FLOAT),
                    ("bytes_per_s", FeatureType.FLOAT),
                    ("avg_ttl", FeatureType.FLOAT),
                    ("iat_std", FeatureType.FLOAT),
                    ("iat_min", FeatureType.FLOAT),
                    ("iat_max", FeatureType.FLOAT),
                    ("iat_sum", FeatureType.FLOAT),
                ],
            )

        names_types = []
        if FeatureSetMode.PORT_DECIMAL not in self.modes:
            names_types += [
                (
                    "src_port",
                    FeatureType.CATEGORIAL
                    if FeatureSetMode.PORT_DECIMAL in self.modes
                    else FeatureType.INT,
                ),
                (
                    "dest_port",
                    FeatureType.CATEGORIAL
                    if FeatureSetMode.PORT_DECIMAL in self.modes
                    else FeatureType.INT,
                ),
            ]
        else:
            names_types += [
                ("src_port_digit_%s" % i, FeatureType.INT) for i in range(8)
            ] + [("dest_port_digit_%s" % i, FeatureType.INT) for i in range(8)]
        names_types += [("protocol", FeatureType.CATEGORIAL)]
        if FeatureSetMode.BASIC not in self.modes:
            names_types += [
                *packet_list_features("total"),
                *packet_list_features("fwd"),
                *packet_list_features("bwd"),
            ]
            if FeatureSetMode.WITH_IP_ADDR in self.modes:
                if FeatureSetMode.IP_DOTTED not in self.modes:
                    names_types += [
                        (
                            "src_ip",
                            FeatureType.INT,
                        ),
                        (
                            "dest_ip",
                            FeatureType.INT,
                        ),
                    ]
                else:
                    names_types += [
                        ("src_ip_dotted_%s" % (17 - i), FeatureType.INT)
                        for i in range(1, 17)
                    ] + [
                        ("dest_ip_dotted_%s" % (17 - i), FeatureType.INT)
                        for i in range(1, 17)
                    ]
            if FeatureSetMode.SUBFLOWS in self.modes:
                names_types += [
                    ("n_subflows", FeatureType.INT),
                    ("n_active_times", FeatureType.INT),
                    ("min_active_time", FeatureType.FLOAT),
                    ("max_active_time", FeatureType.FLOAT),
                    ("total_active_time", FeatureType.FLOAT),
                    ("std_active_time", FeatureType.FLOAT),
                    ("mean_active_time", FeatureType.FLOAT),
                    ("n_idle_times", FeatureType.INT),
                    ("min_idle_time", FeatureType.FLOAT),
                    ("max_idle_time", FeatureType.FLOAT),
                    ("total_idle_time", FeatureType.FLOAT),
                    ("std_idle_time", FeatureType.FLOAT),
                    ("mean_idle_time", FeatureType.FLOAT),
                    ("fwd_subflow_avg_pkts", FeatureType.FLOAT),
                    ("fwd_subflow_avg_length", FeatureType.FLOAT),
                    ("bwd_subflow_avg_pkts", FeatureType.FLOAT),
                    ("bwd_subflow_avg_length", FeatureType.FLOAT),
                ]

            if FeatureSetMode.TCP in self.modes:
                names_types += [
                    ("tcp_fwd_win_mean", FeatureType.FLOAT),
                    ("tcp_fwd_total_urg", FeatureType.INT),
                    ("tcp_fwd_total_syn", FeatureType.INT),
                    ("tcp_fwd_total_syn_ack", FeatureType.INT),
                    ("tcp_fwd_total_ack", FeatureType.INT),
                    ("tcp_fwd_total_fin", FeatureType.INT),
                    ("tcp_fwd_total_push", FeatureType.INT),
                    ("tcp_fwd_total_rst", FeatureType.INT),
                    ("tcp_bwd_win_mean", FeatureType.FLOAT),
                    ("tcp_bwd_total_urg", FeatureType.INT),
                    ("tcp_bwd_total_syn", FeatureType.INT),
                    ("tcp_bwd_total_syn_ack", FeatureType.INT),
                    ("tcp_bwd_total_ack", FeatureType.INT),
                    ("tcp_bwd_total_fin", FeatureType.INT),
                    ("tcp_bwd_total_push", FeatureType.INT),
                    ("tcp_bwd_total_rst", FeatureType.INT),
                    ("tcp_syn_synack", FeatureType.FLOAT),
                    ("tcp_synack_ack", FeatureType.FLOAT),
                    ("tcp_rtt", FeatureType.FLOAT),
                ]
            if FeatureSetMode.HINDSIGHT in self.modes:
                names_types += [
                    ("hindsight_dest_addr_src_port", FeatureType.INT),
                    ("hindsight_src_addr_dest_port", FeatureType.INT),
                    ("hindsight_src_addr", FeatureType.INT),
                    ("hindsight_dest_addr", FeatureType.INT),
                    ("hindsight_dest_addr_prot", FeatureType.INT),
                    ("hindsight_src_addr_prot", FeatureType.INT),
                ]
        names, types = zip(*names_types)
        return list(names), list(types)

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

    def _extract_active_idle_features(self, flow: t.List[IPPacket]):
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
            features += [
                len(time_list),
                min(time_list),
                max(time_list),
                sum(time_list),
                statistics.pstdev(time_list),
                statistics.mean(time_list),
            ]
        return features

    def _extract_subflow_features(self, flow: t.List[IPPacket]):
        subflows = self._make_subflows(flow)
        flow_total_lengths = []
        flow_total_pkts = []
        for subflow in subflows:
            flow_total_pkts.append(len(subflow))
            total_flow_size = sum([self._get_packet_size(packet) for packet in subflow])
            flow_total_lengths.append(total_flow_size)
        return [statistics.mean(flow_total_pkts), statistics.mean(flow_total_lengths)]

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
        return (
            [*length_stats]
            + [n_packets, packets_per_millisecond, bytes_per_millisecond]
            + ip_stats
            + time_stats
        )

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
            # inter_arrival_times cannot be calculated if there is only one packet
            return [NOT_APPLICABLE_FEATURE_VALUE] * 4
        inter_arrival_times = []
        last_ts = packet_list[0][0]
        for ts, packet in packet_list[1:]:
            inter_arrival_times.append(ts - last_ts)
            last_ts = ts
        return [
            statistics.pstdev(inter_arrival_times),
            min(inter_arrival_times),
            max(inter_arrival_times),
            sum(inter_arrival_times),
        ]

    @staticmethod
    def get_name() -> str:
        return "flow_extractor"

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        parser.add_argument(
            "--flow-timeout",
            type=float,
            dest="flow_timeout",
            default=12,
            help="Flow timeout in seconds",
        )
        parser.add_argument(
            "--subflow-timeout",
            type=float,
            dest="subflow_timeout",
            default=0.5,
            help="Activity timeout (for subflows) in seconds",
        )
        parser.add_argument(
            "--hindsight-window",
            type=float,
            dest="hindsight_window",
            default=100,
            help="Hindsight window; only used with netflow mode 'hindsight'",
        )
        parser.add_argument("--verbose", action="store_true", default=False)
        parser.add_argument(
            "--nf-mode",
            choices=[m.value for m in FeatureSetMode],
            nargs="+",
            help="Feature Selection Modes",
            default=[],
        )

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return BasicNetflowFeatureExtractor(
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
            hindsight_window=args.hindsight_window,
            verbose=args.verbose,
            modes=[FeatureSetMode(v) for v in args.nf_mode],
        )

    def __str__(self):
        return self.get_id()

    def get_id(self) -> str:
        modes = sorted([m.value for m in self.modes])
        if FeatureSetMode.SUBFLOWS in self.modes:
            # information about subflows must only be displayed if subflows are actually used
            sf_part = f", sf_timeout={self.subflow_timeout}"
        else:
            sf_part = ""
        if FeatureSetMode.HINDSIGHT in self.modes:
            hindsight_part = f", hindsight_window={self.hindsight_window}"
        else:
            hindsight_part = ""
        return f"FlowExtractor(timeout={self.flow_timeout}, modes={modes}{sf_part}{hindsight_part})"

    def get_db_params_dict(self):
        params = {
            "flow_timeout": self.flow_timeout,
            "subflow_timeout": self.subflow_timeout,
            "hindsight_window": self.hindsight_window,
        }
        for nf_mode in FeatureSetMode:
            params[nf_mode.name] = nf_mode in self.modes
        return params

    def packet_length_stats(self, packets: t.List[IPPacket]) -> PacketLengthStats:
        if len(packets) == 0:
            return PacketLengthStats(*[NOT_APPLICABLE_FEATURE_VALUE] * 5)
        lengths = [self._get_packet_size(packet) for packet in packets]
        return PacketLengthStats(
            total=sum(lengths),
            mean=statistics.mean(lengths),
            min=min(lengths),
            max=max(lengths),
            std=statistics.pstdev(lengths),
        )

    def _get_packet_size(self, packet: IPPacket):
        _, ip = packet
        if FeatureSetMode.INCLUDE_HEADER_LENGTH in self.modes:
            return len(ip)
        else:
            return len(ip.data)

    def validate(self):
        if FeatureSetMode.BASIC in self.modes:
            for mode in self.modes:
                if mode not in [FeatureSetMode.TCP, FeatureSetMode.BASIC]:
                    raise ValueError(
                        f"'{FeatureSetMode.BASIC.value}' can only be specified without any other modes."
                    )
                if mode is FeatureSetMode.TCP:
                    logging.warning(
                        "Using netflow mode 'tcp' in conjunction with 'basic' will only affect the flow creation, not the feature extraction"
                    )
        if (
            FeatureSetMode.IP_DOTTED in self.modes
            and FeatureSetMode.WITH_IP_ADDR not in self.modes
        ):
            raise ValueError(
                f"'Mode {FeatureSetMode.IP_DOTTED.value}' can only be set as a netflow mode if '{FeatureSetMode.WITH_IP_ADDR.value}' is set as well."
            )
        if (
            FeatureSetMode.TCP_END_ON_RST in self.modes
            and FeatureSetMode.TCP not in self.modes
        ):
            f"'Mode {FeatureSetMode.TCP_END_ON_RST.value}' can only be set as a netflow mode if '{FeatureSetMode.TCP.value}' is set as well."


def tcp_timeout_on_FIN(packet: IPPacket, flow: NetFlow, end_on_rst: bool = False):
    """
    Is used for determining when a TCP flow ends. A TCP flow is closed when a FIN packet is observed, even
    if the timeout is not yet exceeded. If end_on_rst is set, then a flow is also ended when the RST flag is observed.
    """
    if flow.protocol != TCP:
        return None
    ts, ip = packet
    tcp = ip.data
    if type(tcp) is not dpkt.tcp.TCP:
        return None
    return tcp.flags & dpkt.tcp.TH_FIN != 0 or (
        end_on_rst and (tcp.flags & dpkt.tcp.TH_RST != 0)
    )


class NetFlowGenerator:
    def __init__(
        self,
        timeout: int = 10_000,
        timeout_fn: t.Optional[t.Callable[[IPPacket], bool]] = None,
    ):
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

    def open_flow(
        self, packet: IPPacket, flow_id: FlowIdentifier, packet_infos: t.Tuple
    ) -> int:
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
            backward_packets_indexes=[],
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

    def make_flow_id(
        self, ip_packet, src_ip, dest_ip, src_port, dest_port, protocol
    ) -> FlowIdentifier:
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

    def get_packet_direction(
        self, packet_info: t.Tuple, flow_id: FlowIdentifier
    ) -> FlowDirection:
        if packet_info[0] == flow_id[0]:
            return FlowDirection.FORWARDS
        else:
            return FlowDirection.BACKWARDS


def get_if_exists(obj, key, default):
    if hasattr(obj, key):
        return obj[key]
    else:
        return default


def is_tcp_syn(tcp: dpkt.tcp.TCP):
    return tcp.flags & dpkt.tcp.TH_SYN != 0 and tcp.flags & dpkt.tcp.TH_ACK == 0


def is_tcp_syn_ack(tcp: dpkt.tcp.TCP):
    return tcp.flags & dpkt.tcp.TH_SYN != 0 and tcp.flags & dpkt.tcp.TH_ACK != 0


def is_tcp_ack(tcp: dpkt.tcp.TCP):
    return tcp.flags & dpkt.tcp.TH_SYN == 0 and tcp.flags & dpkt.tcp.TH_ACK != 0
