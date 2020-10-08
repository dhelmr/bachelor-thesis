import csv
import logging
import math
import os
import re
from enum import Enum
from typing import Optional

import dpkt
import pandas

from anomaly_detection.types import DatasetPreprocessor, TrafficReader, TrafficSequence, DatasetUtils, TrafficType
from dataset_utils import pcap_utils
from dataset_utils.encoding_utils import get_encoding_for_csv

CSV_FOLDER = "UNSW-NB15 - CSV Files"
CSV_FILES = [
    "UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"
]
CSV_FEATURE_NAMES_FILE = "NUSW-NB15_features.csv"
FEATURE_NAME_COLUMN_FIELD = "Name"  # name of the column which specified the feature name in NUSW-NB15_features.csv

PCAP_FILES = {  # TODO use same names as when downloaded properly
    "01": [f"{i}.pcap" for i in range(1, 53)],
    "02": [f"{i}.pcap" for i in range(1, 27)]
}


class FlowCsvColumns(Enum):
    SRC_IP = "srcip"
    SRC_PORT = "sport"
    DEST_IP = "dstip"
    DEST_PORT = "dsport"
    START_TIME = "Stime"
    PROTOCOL = "proto"
    END_TIME = "Ltime"
    ATTACK_CATEGORY = "attack_cat"
    LABEL = "Label"


class UNSWNB15TrafficReader(TrafficReader):

    def read_normal_data(self) -> TrafficSequence:
        pass

    def __iter__(self):
        pass


PROTOCOL_ENCODINGS = {
    "udp": "udp",
    "tcp": "tcp",
    "unknown": "unknown"
}


class UNSWNB15Preprocessor(DatasetPreprocessor):

    def __init__(self):
        self.flow_formatter = pcap_utils.FlowIDFormatter(PROTOCOL_ENCODINGS)

    def preprocess(self, dataset_path: str):
        column_names = self._load_column_names(os.path.join(dataset_path, CSV_FOLDER, CSV_FEATURE_NAMES_FILE))

        flow_features = pandas.concat([
            self._read_flow_labels_csv(os.path.join(dataset_path, CSV_FOLDER, csv), column_names)
            for csv in CSV_FILES
        ], ignore_index=True)
        flow_features.set_index("flow_id", inplace=True)
        attack_times = self._get_attack_flow_ids(flow_features)

        for pcap in self._iter_pcaps(dataset_path):
            self._write_pcap_labels(pcap, attack_times)

    # with ThreadPoolExecutor(max_workers = 10) as pool:
    #     args = [(pcap, attack_times) for pcap in self._iter_pcaps(dataset_path)]
    #     pool.map(self._write_pcap_labels, args)

    def _load_column_names(self, csv_file):
        df = pandas.read_csv(csv_file, sep=",", encoding="latin1")
        column_names = [row[FEATURE_NAME_COLUMN_FIELD].strip() for _, row in df.iterrows()]
        return column_names

    def _read_flow_labels_csv(self, csv_file, column_names, nrows=None, encoding=None) -> pandas.DataFrame:
        logging.debug("Read flow features from %s", csv_file)
        if encoding is None:
            ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            encoding = get_encoding_for_csv(csv_file, lambda df: ip_pattern.match(df[0][0]))
            if encoding is None:
                logging.warning("Cannot determine encoding for %s; use utf_8", csv_file)
                encoding = "utf_8"
        df = pandas.read_csv(csv_file, sep=",", low_memory=False, header=None, names=column_names,
                             encoding=encoding, nrows=nrows)
        df.dropna(how="all", inplace=True)  # drop all empty rows (some csv are miss-formatted)
        df[FlowCsvColumns.LABEL.value] = df[FlowCsvColumns.LABEL.value].apply(self._label_to_traffic_type)
        # make flow ids
        df["flow_id"] = df[FlowCsvColumns.SRC_IP.value] + "-" + df[FlowCsvColumns.DEST_IP.value] + "-" + \
                        df[FlowCsvColumns.SRC_PORT.value].astype(str) + "-" + df[FlowCsvColumns.DEST_PORT.value].astype(
            str) + "-" + \
                        df[FlowCsvColumns.PROTOCOL.value]
        df["reverse_flow_id"] = df[FlowCsvColumns.DEST_IP.value] + "-" + df[FlowCsvColumns.SRC_IP.value] + "-" + \
                                df[FlowCsvColumns.DEST_PORT.value].astype(str) + "-" + df[
                                    FlowCsvColumns.SRC_PORT.value].astype(
            str) + "-" + \
                                df[FlowCsvColumns.PROTOCOL.value]
        return df

    def _iter_pcaps(self, dataset_path: str):
        for folder, pcap_files in PCAP_FILES.items():
            for pcap_file in pcap_files:
                path = os.path.join(dataset_path, folder, pcap_file)
                if os.path.exists(path):
                    yield path
                else:
                    logging.warning("Cannot find %s; skip", path)

    def _write_pcap_labels(self, pcap_file, attack_times):
        reader = pcap_utils.read_pcap_pcapng(pcap_file, print_progress_after=100)
        attack_flow_ids = set(attack_times.index.values)
        output_file = "%s_packet_labels.csv" % pcap_file
        with open(output_file, 'w') as csvfile:
            # creating a csv writer object
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(["packet_id", "traffic_type"])
            index = 0
            for timestamp, buf in reader:
                ids = self.flow_formatter.make_flow_ids(timestamp, buf, packet_type=dpkt.sll.SLL)
                if ids is None:
                    packet_id = "%s-%s-<no_ip>" % (index, timestamp)
                    packet_type = TrafficType.BENIGN
                else:
                    flow_id, reverse_id = ids
                    packet_id = "%s-%s-%s" % (index, flow_id, timestamp)
                    if flow_id not in attack_flow_ids and reverse_id not in attack_flow_ids:
                        packet_type = TrafficType.BENIGN
                    else:
                        potential_attack_flows = attack_times.loc[attack_times.index.isin([flow_id, reverse_id])]
                        attacks = potential_attack_flows["attack"].values[0]
                        benigns = potential_attack_flows["benign"].values[0]
                        if type(benigns) is float and math.isnan(benigns):
                            packet_type = TrafficType.ATTACK
                        elif type(attacks) is float and math.isnan(attacks):
                            packet_type = TrafficType.BENIGN
                        else:
                            packet_type = self.get_traffic_type(timestamp, attacks, benigns)
                            if packet_type is None:
                                logging.error("Could not associate packet %s", flow_id)
                                packet_type = TrafficType.BENIGN
                csvwriter.writerow([packet_id, packet_type.value])

    def get_traffic_type(self, ts, attack_times, benign_times):
        ts = round(ts)
        last_type = None
        while len(attack_times) != 0 or len(benign_times) != 0:
            if len(benign_times) == 0:
                if ts < attack_times[0]:
                    return last_type
                else:
                    return TrafficType.ATTACK
            if len(attack_times) == 0:
                if ts < benign_times[0]:
                    return last_type
                else:
                    return TrafficType.BENIGN
            if attack_times[0] < benign_times[0]:
                time = attack_times.pop(0)
                if ts < time:
                    return last_type
                last_type = TrafficType.ATTACK
            else:
                time = benign_times.pop(0)
                if ts < time:
                    return last_type
                last_type = TrafficType.BENIGN
        return last_type

    def _get_attack_flow_ids(self, flows):
        attacks = flows.loc[flows[FlowCsvColumns.LABEL.value] == TrafficType.ATTACK]
        benigns = flows.loc[flows[FlowCsvColumns.LABEL.value] == TrafficType.BENIGN]
        in_both = pandas.merge(attacks, benigns, how="inner", left_index=True, right_index=True)
        in_both_reversed_id = pandas.merge(attacks, benigns, how="inner", left_on="reverse_flow_id", right_index=True)
        in_both = pandas.concat([in_both, in_both_reversed_id])
        benign_times = in_both[f"{FlowCsvColumns.START_TIME.value}_y"].groupby(in_both.index).apply(
            lambda elements: sorted(list(elements))
        )
        attack_times = attacks[FlowCsvColumns.START_TIME.value].groupby(attacks.index).apply(
            lambda elements: sorted(list(elements))
        )
        result_df = pandas.merge(attack_times, benign_times, how="left", right_index=True, left_index=True)
        result_df.rename(columns={f"{FlowCsvColumns.START_TIME.value}_y": "benign",
                                  FlowCsvColumns.START_TIME.value: "attack"}, inplace=True)
        return result_df

    def _label_to_traffic_type(self, label):
        if label == 0:
            return TrafficType.BENIGN
        else:
            return TrafficType.ATTACK

    def _select_flow(self, potential_flows: pandas.DataFrame, timestamp) -> Optional[pandas.Series]:
        """Selects the flow that contains the given timestamp"""
        for _, flow in potential_flows.iterrows():
            if flow[FlowCsvColumns.START_TIME.value] <= timestamp <= flow[FlowCsvColumns.END_TIME.value]:
                return flow
        return None

UNSWNB15 = DatasetUtils(UNSWNB15TrafficReader, UNSWNB15Preprocessor)
