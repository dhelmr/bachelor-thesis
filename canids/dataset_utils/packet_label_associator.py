import csv
import datetime
import itertools
import logging
import socket
from abc import ABC, abstractmethod
from typing import Tuple, Any, List, Set, Sequence, NamedTuple, Optional

import dpkt as dpkt
import pandas
import pytz

from canids.dataset_utils import pcap_utils
from canids.dataset_utils.pcap_utils import get_ip_packet
from canids.types import Packet, TrafficType

AdditionalInfo = Any

COL_FLOW_ID = "flow_id"
COL_REVERSE_FLOW_ID = "reverse_id"
COL_TRAFFIC_TYPE = "traffic_type"
COL_START_TIME = "start_time"
COL_END_TIME = "end_time"
COL_INFO = "info"
COL_SRC_PKTS = "src_packets"
COL_DEST_PKTS = "dest_packets"
COL_SRC_IP = "src_ip"
COL_SRC_PORT = "src_port"
REQUIRED_COLUMNS = [
    COL_FLOW_ID,
    COL_REVERSE_FLOW_ID,
    COL_TRAFFIC_TYPE,
    COL_START_TIME,
    COL_INFO,
]

DEFAULT_OUTPUT_HEADER = [
    "packet_id",
    "timestamp",
    "flow_id",
    "reverse_flow_id",
    "traffic_type",
]


class SrcIdentification(NamedTuple):
    ip_address: str
    port: int


class FlowIdentification(NamedTuple):
    flow_id: str
    reverse_id: str
    uni_from_src: Optional[SrcIdentification] = None

    def flow_ids_as_list(self):
        return [self.flow_id, self.reverse_id]


class FlowProperties(NamedTuple):
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime]
    additional_info: AdditionalInfo
    traffic_type: TrafficType
    ids: FlowIdentification

    def json_serializable(self) -> dict:
        return {
            "flow_id": self.ids._asdict(),
            "start_time": self.start_time.timestamp(),
            "end_time": self.end_time.timestamp()
            if self.end_time is not None
            else None,
            "additional_info": str(self.additional_info),
            "traffic_type": self.traffic_type.value,
        }


class Report(NamedTuple):
    no_flow_ids: list
    attack_without_flow: list
    duplicate_flows: Set[Tuple[FlowProperties]]
    invalid_flows: Set[FlowProperties]

    def json_serializable(self) -> dict:
        return {
            "attack_without_flow": self.attack_without_flow,
            "no_flow_ids": self.no_flow_ids,
            "duplicate_flows": [
                (f[0].json_serializable(), f[1].json_serializable())
                for f in self.duplicate_flows
            ],
            "invalid_flows": [f.json_serializable() for f in self.invalid_flows],
        }

    @staticmethod
    def empty():
        return Report(
            no_flow_ids=[],
            attack_without_flow=[],
            duplicate_flows=set(),
            invalid_flows=set(),
        )


class PacketLabelAssociator(ABC):
    def __init__(
        self,
        additional_cols=None,
        use_end_time=False,
        find_duplicate_flows=True,
        recognize_uni_flows=True,
    ):
        if additional_cols is None:
            additional_cols = []
        self.csv_header = DEFAULT_OUTPUT_HEADER + additional_cols
        self.find_duplicate_flows = find_duplicate_flows
        self.use_end_time = use_end_time
        self.recognize_uni_flows = recognize_uni_flows
        self.modify_packet = None  # TODO can maybe be removed
        self.report = Report.empty()

    def associate_pcap_labels(self, pcap_file, packet_id_prefix=None):
        logging.info("Preprocess %s" % pcap_file)
        if packet_id_prefix is None:
            packet_id_prefix = pcap_file
        attack_flows, attack_ids = self._get_flows_for_pcap(pcap_file)

        pcap_reader = self._open_pcap(pcap_file)
        with open(self.output_csv_file(pcap_file), "w") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(self.csv_header)
            for i, packet in enumerate(pcap_reader):
                if self.modify_packet is not None:
                    packet = self.modify_packet(packet)
                packet_id = "%s-%s" % (packet_id_prefix, i)
                traffic_type, flow_ids, additional_info = self._associate_packet(
                    packet, packet_id, attack_flows, attack_ids
                )
                if len(flow_ids) == 0:
                    flow_id, reverse_id = "unknown", "unknown"
                elif len(flow_ids) != 2:
                    raise ValueError(
                        "Expected to have either zero or two flow ids for packet %s" % i
                    )
                else:
                    flow_id, reverse_id = flow_ids
                self._write_csv_row(
                    csvwriter,
                    packet_id,
                    packet[0],
                    flow_id,
                    reverse_id,
                    traffic_type,
                    additional_info,
                )

    def _open_pcap(self, pcap_file):
        return pcap_utils.read_pcap_pcapng(pcap_file)

    @abstractmethod
    def _get_flows_for_pcap(self, pcap_file):
        raise NotImplementedError()  # set(attack_flows.index.values)

    def _validate_flow_infos(self, flow_infos: pandas.DataFrame):
        expected_cols = REQUIRED_COLUMNS
        if self.use_end_time:
            expected_cols += [COL_END_TIME]
        if self.recognize_uni_flows:
            expected_cols += [COL_SRC_PORT, COL_SRC_PKTS, COL_DEST_PKTS]
        for col in REQUIRED_COLUMNS:
            if col != COL_FLOW_ID and col not in flow_infos.columns:
                raise ValueError(
                    "Expected column %s to be present in flow infos!" % col
                )

    @abstractmethod
    def make_flow_ids(self, packet: Packet) -> FlowIdentification:
        raise NotImplementedError()

    def _find_attack_flows(self, flows) -> Tuple[pandas.DataFrame, Set[str]]:
        """
        Takes a dataframe with flow information and extracts all attack flows, together with their starting times.
        If there are benign flows under the same, or reversed flow id, the corresponding starting times are returned as
         well
        :param flows: A pandas dataframe with the flow information. It needs to pass _validate_flow_infos
        :return: A pandas dataframe with the flow_ids of all attacks as its index and two columns: "attack" and "benign".
         Each cell contains a list of tuples (start_time, info). Each tuple indicates an flow of the respective traffic
         type.
        Cells of the "benign" category can have the value nan. Keep in mind that a packet can have two possible flow ids
        """
        self._validate_flow_infos(flows)
        attacks = flows.loc[flows[COL_TRAFFIC_TYPE] == TrafficType.ATTACK]
        benigns = flows.loc[flows[COL_TRAFFIC_TYPE] == TrafficType.BENIGN]
        in_both = pandas.merge(
            attacks, benigns, how="inner", left_index=True, right_index=True
        )
        in_both_reversed_id = pandas.merge(
            attacks, benigns, how="inner", left_on=COL_REVERSE_FLOW_ID, right_index=True
        )
        in_both = pandas.concat([in_both, in_both_reversed_id])

        benign_times = in_both.groupby(in_both.index).apply(
            lambda elements: sorted(
                list(
                    {
                        self._make_flow_properties(
                            row, traffic_type=TrafficType.BENIGN, col_suffix="_y"
                        )
                        for _, row in elements.iterrows()
                    }
                ),
                key=lambda item: item.start_time,
            )
        )
        attack_times = attacks.groupby(attacks.index).apply(
            lambda elements: sorted(
                list(
                    {
                        self._make_flow_properties(row, traffic_type=TrafficType.ATTACK)
                        for _, row in elements.iterrows()
                    }
                ),
                key=lambda item: item.start_time,
            )
        )
        # convert to Series in case that no items where found; groupby yields an empty Dataframe then
        if len(attack_times) == 0:
            attack_times = pandas.Series()
        if len(benign_times) == 0:
            benign_times = pandas.Series()
        result_df = pandas.merge(
            attack_times.to_frame("attack"),
            benign_times.to_frame("benign"),
            how="left",
            right_index=True,
            left_index=True,
        )
        return result_df, set(result_df.index.values.tolist())

    def _make_flow_properties(
        self, row: pandas.Series, traffic_type: TrafficType, col_suffix=""
    ):
        def get_field(name):
            key = f"{name}{col_suffix}"
            return row[key]

        if (
            self.recognize_uni_flows
            and get_field(COL_SRC_PKTS) > 0
            and get_field(COL_DEST_PKTS) == 0
        ):
            # if the flow is unidirectional, store its source address explicitely
            # otherwise, the source address cannot be determined for sure from only the flow id
            uni_flow_src = SrcIdentification(
                ip_address=get_field(COL_SRC_IP), port=get_field(COL_SRC_PORT)
            )
        else:
            uni_flow_src = None

        if self.use_end_time:
            end_time = self._date_cell_to_timestamp(get_field(COL_END_TIME))
        else:
            end_time = None

        return FlowProperties(
            ids=FlowIdentification(
                flow_id=row.name,
                reverse_id=get_field(COL_REVERSE_FLOW_ID),
                uni_from_src=uni_flow_src,
            ),
            start_time=self._date_cell_to_timestamp(get_field(COL_START_TIME)),
            end_time=end_time,
            additional_info=get_field(COL_INFO),
            traffic_type=traffic_type,
        )

    def _associate_packet(
        self, packet, packet_id, attack_flows, attack_ids
    ) -> Tuple[TrafficType, Sequence[str], AdditionalInfo]:
        """
        Finds the corresponding labels for a packet, i.e. whether it belongs to an attack or benign traffic and, if it
        belongs to an attack, additional info about that
        :param packet:  the packet which should be labelled
        :param attack_flows:    A pandas dataframe with information about the attack flows,
        should be a result of _find_attack_flows
        :param attack_ids: A set with all attack ids
        :return: A tuple (traffic_type, flow_ids, info) where flow_ids is None if no flow_ids is empty if no flow ids can
        be generated
        """
        timestamp, buffer = packet
        flow_ids = self.make_flow_ids(
            packet
        )  # TODO must be rewritten in cicids2017 and unsw
        if flow_ids is None:
            self.report.no_flow_ids.append((packet[0], packet_id))
            return TrafficType.BENIGN, [], None
        if flow_ids.flow_id not in attack_ids and flow_ids.reverse_id not in attack_ids:
            return TrafficType.BENIGN, flow_ids.flow_ids_as_list(), None

        flow_ids_list = flow_ids.flow_ids_as_list()
        potential_flows_df = attack_flows.loc[attack_flows.index.isin(flow_ids_list)]
        potential_flows = sorted(
            itertools.chain(
                *(potential_flows_df["attack"].dropna().values.tolist()),
                *(potential_flows_df["benign"].dropna().values.tolist()),
            ),
            key=lambda item: item.start_time,
        )
        if self.recognize_uni_flows:
            potential_flows = self._filter_unidirectional(
                flow_ids.uni_from_src, potential_flows
            )
        if self.find_duplicate_flows:
            self._find_duplicate_flows(potential_flows)

        timestamp = datetime.datetime.fromtimestamp(timestamp).astimezone(tz=pytz.utc)
        matched_flow = self._match_flow(timestamp, potential_flows)
        if matched_flow is None:
            self.report.attack_without_flow.append(
                (packet[0], packet_id, flow_ids_list)
            )
            return TrafficType.BENIGN, flow_ids_list, None
        return matched_flow.traffic_type, flow_ids_list, matched_flow.additional_info

    def _find_duplicate_flows(self, flows: List[FlowProperties]):
        for i, selected_flow in enumerate(flows):
            if self.use_end_time and selected_flow.end_time < selected_flow.start_time:
                self.report.invalid_flows.add(selected_flow)
                continue
            next_flow_i = i + 1
            for other_flow in flows[next_flow_i:]:
                if self.use_end_time and other_flow.start_time < selected_flow.end_time:
                    self.report.duplicate_flows.add((selected_flow, other_flow))
                elif other_flow.start_time == selected_flow.start_time:
                    self.report.duplicate_flows.add((selected_flow, other_flow))

    def _match_flow(
        self, ts: datetime.datetime, sorted_flows: List[FlowProperties]
    ) -> Optional[FlowProperties]:
        last_flow = None
        for flow in sorted_flows:
            if flow.start_time > ts:
                return last_flow
            if not self.use_end_time or flow.end_time >= ts:
                last_flow = flow
        return last_flow

    @abstractmethod
    def output_csv_file(self, pcap_file) -> str:
        """
        Returns the csv file where the packet labels will be written into
        :param pcap_file: Corresponding pcap file that contains the packets
        :return: filename of the csv file
        """
        raise NotImplementedError()

    def _write_csv_row(
        self,
        csv_writer,
        packet_id,
        ts,
        flow_id,
        reverse_id,
        traffic_type,
        additional_info,
    ):
        if type(additional_info) is not str:
            additional_cells = ""
        else:
            additional_cells = self._unpack_additional_info(additional_info)
        csv_writer.writerow(
            [packet_id, ts, flow_id, reverse_id, traffic_type.value, *additional_cells]
        )

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        """ Is called when the timestamp of an attack is read from the flow infos """
        raise NotImplementedError()

    def _drop_non_required_cols(self, df: pandas.DataFrame):
        keep_cols = REQUIRED_COLUMNS + [
            COL_END_TIME,
            COL_SRC_IP,
            COL_SRC_PKTS,
            COL_DEST_PKTS,
            COL_SRC_PORT,
        ]
        columns_to_drop = [col for col in df.columns if col not in keep_cols]
        df.drop(columns=columns_to_drop, inplace=True)

    @abstractmethod
    def _unpack_additional_info(self, additional_info: AdditionalInfo) -> List[str]:
        raise NotImplementedError()

    def _filter_unidirectional(
        self, packet_src: SrcIdentification, potential_flows: List[FlowProperties]
    ):
        if not self.recognize_uni_flows:
            return potential_flows
        return [
            f
            for f in potential_flows
            if f.ids.uni_from_src is None or f.ids.uni_from_src == packet_src
        ]


class FlowIDFormatter:
    def __init__(self):
        self.protocol_converter = lambda x: x

    def make_flow_ids(self, ts, buf, packet_type=dpkt.ethernet.Ethernet):
        ip = get_ip_packet(buf, linklayer_hint=packet_type)
        if ip is None:
            return None
        src_ip = socket.inet_ntoa(ip.src)
        dest_ip = socket.inet_ntoa(ip.dst)
        src_port = get_if_exists(ip.data, "sport", 0)
        dest_port = get_if_exists(
            ip.data, "dport", 0
        )  # TODO CHeck if ICMP in cic-ids-2017 uses port 0
        protocol = self.protocol_converter(ip.p)
        return FlowIdentification(
            flow_id=self.format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol),
            reverse_id=self.format_flow_id(
                src_ip, dest_ip, src_port, dest_port, protocol, reverse=True
            ),
            uni_from_src=SrcIdentification(ip_address=src_ip, port=src_port),
        )

    def format_flow_id(
        self, src_ip, dest_ip, src_port, dest_port, protocol, reverse=False
    ):
        if not reverse:
            return "%s-%s-%s-%s-%s" % (src_ip, dest_ip, src_port, dest_port, protocol)
        return "%s-%s-%s-%s-%s" % (dest_ip, src_ip, dest_port, src_port, protocol)


def get_if_exists(obj, key, default):
    if hasattr(obj, key):
        return obj[key]
    else:
        return default
