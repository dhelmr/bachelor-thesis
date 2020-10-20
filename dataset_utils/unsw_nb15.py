import csv
import datetime
import itertools
import json
import logging
import os
import re
from enum import Enum
from typing import Optional, List

import dpkt
import pandas
from pandas import Series

from anomaly_detection.types import DatasetPreprocessor, TrafficReader, TrafficSequence, DatasetUtils, TrafficType
from dataset_utils import pcap_utils
from dataset_utils.encoding_utils import get_encoding_for_csv
from dataset_utils.pcap_utils import SubsetPacketReader
from dataset_utils.reader_utils import packet_is_attack, ranges_of_list

CSV_FOLDER = "UNSW-NB15 - CSV Files"
CSV_FILES = [
    "UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"
]
CSV_FEATURE_NAMES_FILE = "NUSW-NB15_features.csv"
FEATURE_NAME_COLUMN_FIELD = "Name"  # name of the column which specified the feature name in NUSW-NB15_features.csv
RANGES_FILE = "ranges.json"

PCAP_FILES = {  # TODO use same names as when downloaded properly
    "01": [f"{i}.pcap" for i in range(1, 53)],
    "02": [f"{i}.pcap" for i in range(1, 27)]
}

BENIGN_INDEX_UNTIL = 10  # the first n pcap files are used for the benign dataset part (training set)

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

    def __init__(self, directory: str, subset: str):
        super().__init__(directory, subset)
        self.ranges = self._load_ranges()
        self.subset = self._load_subset(self.subset_name, ranges=self.ranges)

    def read_normal_data(self) -> TrafficSequence:
        # TODO refactor with cic-ids-2017
        traffic_sequences = [self._make_traffic_sequence(pcap_file, ranges) for pcap_file, ranges in
                             self.subset["benign"].items() if os.path.exists(pcap_file)]
        if len(traffic_sequences) == 1:
            return traffic_sequences[0]
        # if more than one traffic sequences are present, join them into one.
        joined_ids = [id_item for id_item in itertools.chain(*map(lambda seq: seq.ids, traffic_sequences))]
        joined_labels = Series()
        for traffic_sequence in traffic_sequences:
            joined_labels = joined_labels.append(traffic_sequence.labels)
        joined_reader = itertools.chain(*map(lambda seq: seq.packet_reader, traffic_sequences))
        return TrafficSequence(name=f"benign@UNSW-NB15:{self.subset_name}",
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               ids=joined_ids)

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            if not os.path.exists(pcap_file):
                continue
            yield self._make_traffic_sequence(pcap_file, ranges)

    def _make_traffic_sequence(self, pcap_file: str, ranges) -> TrafficSequence:
        labels = read_packet_labels(pcap_file)["traffic_type"]
        ids = ranges_of_list(labels.index.values.tolist(), ranges)
        name = f"{pcap_file}@UNSW-NB15:{self.subset_name}"
        packet_reader = SubsetPacketReader(pcap_file, ranges)
        return TrafficSequence(name=name, packet_reader=packet_reader, labels=labels, ids=ids)

    def _load_ranges(self):
        path = os.path.join(self.dataset_dir, RANGES_FILE)
        with open(path, "r") as f:
            return json.load(f)

    def _load_subset(self, subset_name: str, ranges):
        if subset_name == "all" or subset_name == "default":
            return ranges
        # else: subset name must be of parttern "[test split]/[attack file1],[attack file2],..."
        benign, unknown = subset_name.split("/")
        benign_pcaps = self.select_pcaps(benign.split(","))
        unknown_pcaps = self.select_pcaps(unknown.split(","))
        return {
            "benign": {pcap: r for pcap, r in ranges["benign"].items() if pcap in benign_pcaps},
            "unknown": {pcap: r for pcap, r in ranges["unknown"].items() if pcap in unknown_pcaps},
        }

    def select_pcaps(self, patterns: List[str]):
        selected = []
        for pattern in patterns:
            if "-" in pattern:
                start, end = pattern.split("-")
                indexes = range(int(start), int(end) + 1)
            else:
                indexes = [int(pattern)]
            index = 1
            for pcap in iter_pcaps(self.dataset_dir, skip_not_found=False):
                if index in indexes:
                    selected.append(pcap)
                index += 1
        return selected

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

        for pcap in iter_pcaps(dataset_path):
            self._write_pcap_labels(pcap, attack_times)

        ranges = self._make_ranges(dataset_path)
        ranges_path = os.path.join(dataset_path, RANGES_FILE)
        with open(ranges_path, "w") as f:
            json.dump(ranges, f)

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
        df[FlowCsvColumns.LABEL.value] = df[FlowCsvColumns.LABEL.value].apply(label_to_traffic_type)
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

    def _write_pcap_labels(self, pcap_file, attack_times):
        reader = pcap_utils.read_pcap_pcapng(pcap_file, print_progress_after=100)
        attack_flow_ids = set(attack_times.index.values)
        output_file = packet_label_file(pcap_file)
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
                        timestamp = round(timestamp)
                        packet_type = packet_is_attack(ids, timestamp, attack_times)
                csvwriter.writerow([packet_id, packet_type.value])
                index += 1

    def _get_attack_flow_ids(self, flows):
        attacks = flows.loc[flows[FlowCsvColumns.LABEL.value] == TrafficType.ATTACK]
        benigns = flows.loc[flows[FlowCsvColumns.LABEL.value] == TrafficType.BENIGN]
        in_both = pandas.merge(attacks, benigns, how="inner", left_index=True, right_index=True)
        in_both_reversed_id = pandas.merge(attacks, benigns, how="inner", left_on="reverse_flow_id", right_index=True)
        in_both = pandas.concat([in_both, in_both_reversed_id])
        benign_times = in_both[f"{FlowCsvColumns.START_TIME.value}_y"].groupby(in_both.index).apply(
            lambda elements: sorted([self.date_to_timestamp(e) for e in list(elements)])
        )
        attack_times = attacks[FlowCsvColumns.START_TIME.value].groupby(attacks.index).apply(
            lambda elements: sorted([self.date_to_timestamp(e) for e in list(elements)])
        )
        result_df = pandas.merge(attack_times, benign_times, how="left", right_index=True, left_index=True)
        result_df.rename(columns={f"{FlowCsvColumns.START_TIME.value}_y": "benign",
                                  FlowCsvColumns.START_TIME.value: "attack"}, inplace=True)
        return result_df

    def _select_flow(self, potential_flows: pandas.DataFrame, timestamp) -> Optional[pandas.Series]:
        """Selects the flow that contains the given timestamp"""
        for _, flow in potential_flows.iterrows():
            if flow[FlowCsvColumns.START_TIME.value] <= timestamp <= flow[FlowCsvColumns.END_TIME.value]:
                return flow
        return None

    def _make_ranges(self, dataset_path) -> dict:
        ranges = {
            "benign": {},
            "unknown": {}
        }
        index = 0
        for pcap in iter_pcaps(dataset_path, skip_not_found=False):
            if index < BENIGN_INDEX_UNTIL:
                if os.path.exists(pcap):
                    ranges["benign"][pcap] = self.find_ranges_of_type(pcap, TrafficType.BENIGN)
                else:
                    logging.info("%s not found", pcap)
            else:
                ranges["unknown"][pcap] = [[0, "end"]]
            index += 1
        return ranges

    def find_ranges_of_type(self, pcap, traffic_type) -> list:
        """ finds consecutive sequences of packets inside the pcap that belong to a specific traffic type"""
        labels = read_packet_labels(pcap)
        current_start = None
        ranges = []
        index = 0
        for _, row in labels.iterrows():
            if row["traffic_type"] is traffic_type and current_start is None:
                current_start = index
            elif row["traffic_type"] is not traffic_type and current_start is not None:
                ranges.append([current_start, index])
                current_start = None
            index += 1
        return ranges

    def date_to_timestamp(self, epoch_time):
        return datetime.datetime.utcfromtimestamp(epoch_time)


def iter_pcaps(dataset_path: str, skip_not_found=True):
    for folder, pcap_files in PCAP_FILES.items():
        for pcap_file in pcap_files:
            path = os.path.join(dataset_path, folder, pcap_file)
            if not skip_not_found or os.path.exists(path):
                yield path
            else:
                logging.warning("Cannot find %s; skip", path)


def read_packet_labels(pcap) -> pandas.DataFrame:
    csv_file = packet_label_file(pcap)
    label_rows = pandas.read_csv(csv_file, sep=",", index_col=0)
    label_rows["traffic_type"] = label_rows["traffic_type"].apply(lambda cell: TrafficType(cell))
    return label_rows


def label_to_traffic_type(label):
    if label == 0:
        return TrafficType.BENIGN
    else:
        return TrafficType.ATTACK


def packet_label_file(pcap_file):
    return "%s_packet_labels.csv" % pcap_file


UNSWNB15 = DatasetUtils(os.path.join("data", "unsw-nb15"), UNSWNB15TrafficReader, UNSWNB15Preprocessor)
