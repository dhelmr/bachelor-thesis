import csv
import datetime
import itertools
import logging
from abc import ABC, abstractmethod
from typing import Tuple, Any, List, Set, Sequence, NamedTuple, Optional

import pandas
import pytz

from canids.dataset_utils import pcap_utils
from canids.types import Packet, TrafficType

AdditionalInfo = Any

COL_FLOW_ID = "flow_id"
COL_REVERSE_FLOW_ID = "reverse_id"
COL_TRAFFIC_TYPE = "traffic_type"
COL_START_TIME = "start_time"
COL_END_TIME = "end_time"
COL_INFO = "info"
REQUIRED_COLUMNS = [
    COL_FLOW_ID,
    COL_REVERSE_FLOW_ID,
    COL_TRAFFIC_TYPE,
    COL_START_TIME,
    COL_INFO,
]

DEFAULT_OUTPUT_HEADER = ["packet_id", "flow_id", "reverse_flow_id", "traffic_type"]


class FlowIdentification(NamedTuple):
    start_time: datetime.datetime
    additional_info: AdditionalInfo
    traffic_type: TrafficType


class PacketLabelAssociator(ABC):
    def __init__(self, additional_cols=None):
        if additional_cols is None:
            additional_cols = []
        self.csv_header = DEFAULT_OUTPUT_HEADER + additional_cols
        self.modify_packet = None  # TODO can maybe be removed

    def associate_pcap_labels(self, pcap_file, packet_id_prefix=None):
        logging.info("Preprocess %s" % pcap_file)
        if packet_id_prefix is None:
            packet_id_prefix = pcap_file
        attack_flows, attack_ids = self._get_attack_flows(pcap_file)

        pcap_reader = self._open_pcap(pcap_file)
        with open(self.output_csv_file(pcap_file), "w") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(self.csv_header)
            for i, packet in enumerate(pcap_reader):
                if self.modify_packet is not None:
                    packet = self.modify_packet(packet)
                packet_id = "%s-%s" % (packet_id_prefix, i)
                traffic_type, flow_ids, additional_info = self._associate_packet(
                    packet, attack_flows, attack_ids
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
                    flow_id,
                    reverse_id,
                    traffic_type,
                    additional_info,
                )

    def _open_pcap(self, pcap_file):
        return pcap_utils.read_pcap_pcapng(pcap_file)

    @abstractmethod
    def _get_attack_flows(self, pcap_file):
        raise NotImplementedError()  # set(attack_flows.index.values)

    def _validate_flow_infos(self, flow_infos: pandas.DataFrame):
        for col in REQUIRED_COLUMNS:
            if col != COL_FLOW_ID and col not in flow_infos.columns:
                raise ValueError(
                    "Expected column %s to be present in flow infos!" % col
                )

    @abstractmethod
    def make_flow_ids(self, packet: Packet) -> Tuple[str, str]:
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
                        FlowIdentification(
                            start_time=self._date_cell_to_timestamp(
                                r[f"{COL_START_TIME}_y"]
                            ),
                            additional_info=r[f"{COL_INFO}_y"],
                            traffic_type=TrafficType.BENIGN,
                        )
                        for _, r in elements.iterrows()
                    }
                ),
                key=lambda item: item.start_time,
            )
        )
        attack_times = attacks.groupby(attacks.index).apply(
            lambda elements: sorted(
                list(
                    {
                        FlowIdentification(
                            start_time=self._date_cell_to_timestamp(r[COL_START_TIME]),
                            additional_info=r[COL_INFO],
                            traffic_type=TrafficType.ATTACK,
                        )
                        for _, r in elements.iterrows()
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

    def _associate_packet(
        self, packet, attack_flows, attack_ids
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
        flow_ids = self.make_flow_ids(packet)
        if flow_ids is None or len(flow_ids) == 0:
            return TrafficType.BENIGN, [], None
        flow_id, reverse_id = flow_ids
        if flow_id not in attack_ids and reverse_id not in attack_ids:
            return TrafficType.BENIGN, flow_ids, None

        potential_attack_flows = attack_flows.loc[attack_flows.index.isin(flow_ids)]
        attacks = list(
            sorted(
                itertools.chain(
                    *(potential_attack_flows["attack"].dropna().values.tolist())
                ),
                key=lambda item: item.start_time,
            )
        )
        benigns = list(
            sorted(
                itertools.chain(
                    *(potential_attack_flows["benign"].dropna().values.tolist())
                ),
                key=lambda item: item.start_time,
            )
        )

        timestamp = datetime.datetime.fromtimestamp(timestamp).astimezone(tz=pytz.utc)
        attack_info = self._is_attack(timestamp, attacks, benigns)
        return attack_info[0], flow_ids, attack_info[1]

    def _is_attack(
        self,
        ts: datetime.datetime,
        attack_times: List[FlowIdentification],
        benign_times: List[FlowIdentification],
    ) -> Optional[FlowIdentification]:
        """
        Checks if a packet's timestamp lies within an attack or benign flow
        :param ts: Timestamp of the packet in question
        :param attack_times: Ordered List that contains an tuple (start_time, info) for each attack flows
        :param benign_times:  Ordered List that contains an tuple (start_time, info) for each benign flows
        :return: A tuple (traffic_type, info), where 'traffic_type' and 'info' is taken from the found flow. If no
        matching flow is found (if the timestamp is before the first attack or benign flow,
        (TrafficType.BENIGN, None) is returned.
        """
        attack_times, benign_times = attack_times.copy(), benign_times.copy()
        last_item = (TrafficType.BENIGN, (None, None))
        while len(attack_times) != 0 or len(benign_times) != 0:
            if len(attack_times) > 0 and (
                len(benign_times) == 0 or attack_times[0][0] < benign_times[0][0]
            ):
                item = attack_times.pop(0)
                if ts < item[0]:
                    return last_item[0], last_item[1][1]
                last_item = (TrafficType.ATTACK, item)
            else:
                item = benign_times.pop(0)
                if ts < item[0]:
                    return last_item[0], last_item[1][1]
                last_item = (TrafficType.BENIGN, item)

        return last_item[0], last_item[1][1]

    @abstractmethod
    def output_csv_file(self, pcap_file) -> str:
        """
        Returns the csv file where the packet labels will be written into
        :param pcap_file: Corresponding pcap file that contains the packets
        :return: filename of the csv file
        """
        raise NotImplementedError()

    def _write_csv_row(
        self, csv_writer, packet_id, flow_id, reverse_id, traffic_type, additional_info
    ):
        if type(additional_info) is not str:
            additional_cells = ""
        else:
            additional_cells = self._unpack_additional_info(additional_info)
        csv_writer.writerow(
            [packet_id, flow_id, reverse_id, traffic_type.value, *additional_cells]
        )

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        """ Is called when the timestamp of an attack is read from the flow infos """
        raise NotImplementedError()

    def _drop_non_required_cols(self, df: pandas.DataFrame):
        columns_to_drop = [col for col in df.columns if col not in REQUIRED_COLUMNS]
        df.drop(columns=columns_to_drop, inplace=True)

    @abstractmethod
    def _unpack_additional_info(self, additional_info: AdditionalInfo) -> List[str]:
        raise NotImplementedError()
