import csv
import datetime
import math
from abc import ABC, abstractmethod
from typing import Tuple, Any, List, Optional, Set

import pandas

from anomaly_detection.types import Packet, TrafficType
from dataset_utils import pcap_utils

AdditionalInfo = Any

COL_FLOW_ID = "flow_id"
COL_REVERSE_FLOW_ID = "reverse_id"
COL_TRAFFIC_TYPE = "traffic_type"
COL_START_TIME = "start_time"
COL_INFO = "info"
REQUIRED_COLUMNS = [COL_FLOW_ID, COL_REVERSE_FLOW_ID, COL_TRAFFIC_TYPE, COL_START_TIME, COL_INFO]

DEFAULT_HEADER = ["packet_id", "traffic_type"]


class PacketLabelAssociator(ABC):

    def __init__(self, csv_header=None):
        if csv_header is None:
            csv_header = DEFAULT_HEADER
        self.csv_header = csv_header

    def associate_pcap_labels(self, pcap_file):
        attack_flows, attack_ids = self.get_attack_flows(pcap_file)

        pcap_reader = pcap_utils.read_pcap_pcapng(pcap_file)
        with open(self.output_csv_file(pcap_file), "w") as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(self.csv_header)
            for i, packet in enumerate(pcap_reader):
                packet_id = "%s-%s" % (pcap_file, i)
                traffic_type, additional_info = self.associate_packet(packet, attack_flows, attack_ids)
                self.write_csv_row(csvwriter, packet_id, traffic_type, additional_info)

    @abstractmethod
    def get_attack_flows(self, pcap_file):
        raise NotImplementedError()  # set(attack_flows.index.values)

    def _validate_flow_infos(self, flow_infos: pandas.DataFrame):
        for col in REQUIRED_COLUMNS:
            if col != COL_FLOW_ID and col not in flow_infos.columns:
                raise ValueError("Expected column %s to be present in flow infos!" % col)

    @abstractmethod
    def make_flow_ids(self, packet: Packet) -> Tuple[str, str]:
        raise NotImplementedError()

    def associate_packet(self, packet, attack_flows, attack_ids) -> Tuple[TrafficType, AdditionalInfo]:
        timestamp, buffer = packet
        flow_ids = self.make_flow_ids(packet)
        if flow_ids is None or len(flow_ids) == 0:
            return TrafficType.BENIGN, None
        flow_id, reverse_id = flow_ids
        if flow_id not in attack_ids and reverse_id not in attack_ids:
            return TrafficType.BENIGN, None

        timestamp = round(timestamp)
        potential_attack_flows = attack_flows.loc[attack_flows.index.isin(flow_ids)]
        attacks = potential_attack_flows["attack"].values[0]
        benigns = potential_attack_flows["benign"].values[0]
        if type(attacks) is float and math.isnan(attacks):
            return TrafficType.BENIGN, None
        if type(benigns) is float and math.isnan(benigns):
            benigns = []

        timestamp = datetime.datetime.utcfromtimestamp(timestamp)
        attack_info = self.is_attack(timestamp, attacks, benigns)
        return attack_info

    def is_attack(self, ts: datetime.datetime,
                  attack_times: List[Tuple[datetime.datetime, AdditionalInfo]],
                  benign_times: List[Tuple[datetime.datetime, AdditionalInfo]]) -> Optional[
        Tuple[TrafficType, AdditionalInfo]]:
        last_item = (TrafficType.BENIGN, (None, None))
        while len(attack_times) != 0 or len(benign_times) != 0:
            if len(attack_times) > 0 and (len(benign_times) == 0 or attack_times[0][0] < benign_times[0][0]):
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
        raise NotImplementedError()

    @abstractmethod
    def write_csv_row(self, csv_writer, packet_id, traffic_type, additional_info):
        raise NotImplementedError()

    def date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        """ Is called when the timestamp of an attack is read from the flow infos """
        raise NotImplementedError()

    def find_attack_flows(self, flows) -> Tuple[pandas.DataFrame, Set[str]]:
        self._validate_flow_infos(flows)
        attacks = flows.loc[flows[COL_TRAFFIC_TYPE] == TrafficType.ATTACK]
        benigns = flows.loc[flows[COL_TRAFFIC_TYPE] == TrafficType.BENIGN]
        in_both = pandas.merge(attacks, benigns, how="inner", left_index=True, right_index=True)
        in_both_reversed_id = pandas.merge(attacks, benigns, how="inner", left_on=COL_REVERSE_FLOW_ID, right_index=True)
        in_both = pandas.concat([in_both, in_both_reversed_id])

        benign_times = in_both.groupby(in_both.index).apply(
            lambda elements: sorted([
                (self.date_cell_to_timestamp(r[f"{COL_START_TIME}_y"]), r[f"{COL_INFO}_y"]) for _, r in
                elements.iterrows()
            ], key=lambda item: item[0])
        )
        attack_times = attacks.groupby(attacks.index).apply(
            lambda elements: sorted([
                (self.date_cell_to_timestamp(r[f"{COL_START_TIME}"]), r[f"{COL_INFO}"]) for _, r in elements.iterrows()
            ], key=lambda item: item[0])
        )
        # convert to Series in case that no items where found; groupby yields an empty Dataframe then
        if len(attack_times) == 0:
            attack_times = pandas.Series()
        if len(benign_times) == 0:
            benign_times = pandas.Series()
        result_df = pandas.merge(attack_times.to_frame("attack"), benign_times.to_frame("benign"), how="left",
                                 right_index=True, left_index=True)
        return result_df, set(result_df.index.values.tolist())

    def drop_non_required_cols(self, df: pandas.DataFrame):
        columns_to_drop = [col for col in df.columns if col not in REQUIRED_COLUMNS]
        df.drop(columns=columns_to_drop, inplace=True)
