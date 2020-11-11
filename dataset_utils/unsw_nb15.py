import argparse
import datetime
import itertools
import json
import logging
import os
import re
import socket
from enum import Enum
from typing import List, Tuple

import dpkt
import pandas
from pandas import Series

from anomaly_detection.types import DatasetPreprocessor, TrafficReader, TrafficSequence, DatasetUtils, TrafficType, \
    Packet
from dataset_utils import pcap_utils
from dataset_utils.PacketLabelAssociator import PacketLabelAssociator, COL_FLOW_ID, COL_REVERSE_FLOW_ID, \
    COL_START_TIME, COL_INFO, COL_TRAFFIC_TYPE, AdditionalInfo
from dataset_utils.encoding_utils import get_encoding_for_csv
from dataset_utils.pcap_utils import SubsetPacketReader
from dataset_utils.reader_utils import ranges_of_list

CSV_FOLDER = "UNSW-NB15 - CSV Files"
CSV_FILES = [
    "UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"
]
CSV_FEATURE_NAMES_FILE = "NUSW-NB15_features.csv"
FEATURE_NAME_COLUMN_FIELD = "Name"  # name of the column which specified the feature name in NUSW-NB15_features.csv
RANGES_FILE = "ranges.json"

PCAP_FILES = {  # TODO use same names as when downloaded properly
    "01": [f"{i}.pcap" for i in range(1, 54)],
    "02": [f"{i}.pcap" for i in range(1, 28)]
}

DEFAULT_BENIGN_PCAPS = [
    "01/10.pcap", "01/11.pcap", "01/12.pcap", "01/13.pcap", "01/26.pcap", "01/27.pcap", "01/40.pcap", "01/41.pcap",
    "01/42.pcap"
]

TINY_SUBSET = {
    "benign": {
        "01/1.pcap": [[0, 200]]
    },
    "unknown": {
        "01/1.pcap": [[400, 1000]]
    }
}


class FlowCsvColumns(Enum):
    SRC_IP = "srcip"
    SRC_PORT = "sport"
    DEST_IP = "dstip"
    DEST_PORT = "dsport"
    SOURCE_PKT_COUNT = "Spkts"
    DEST_PKT_COUNT = "Dpkts"
    START_TIME = "Stime"
    PROTOCOL = "proto"
    END_TIME = "Ltime"
    ATTACK_CATEGORY = "attack_cat"
    LABEL = "Label"
    ""


class UNSWNB15TrafficReader(TrafficReader):

    def __init__(self, directory: str, subset: str):
        super().__init__(directory, subset)
        self.ranges = self._load_ranges()
        self.subset = self._load_subset(self.subset_name, ranges=self.ranges)

    def read_normal_data(self) -> TrafficSequence:
        # TODO refactor with cic-ids-2017
        traffic_sequences = [self._make_traffic_sequence(pcap_file, ranges, "benign") for pcap_file, ranges in
                             self.subset["benign"].items() if os.path.exists(os.path.join(self.dataset_dir, pcap_file))]
        if len(traffic_sequences) == 1:
            return traffic_sequences[0]
        # if more than one traffic sequences are present, join them into one.
        joined_ids = [id_item for id_item in itertools.chain(*map(lambda seq: seq.ids, traffic_sequences))]
        joined_labels = Series()
        for traffic_sequence in traffic_sequences:
            joined_labels = joined_labels.append(traffic_sequence.labels)
        joined_reader = itertools.chain(*map(lambda seq: seq.packet_reader, traffic_sequences))
        parts = {
            "all": joined_ids
        }
        # make sure that the same pcaps, even in different order, result in the same traffic sequence name; regardless
        # of the used test pcaps
        name_identifier = ",".join(sorted([t.name.split(".pcap")[0] for t in traffic_sequences]))
        return TrafficSequence(name=f"benign@UNSW-NB15:%s" % name_identifier,
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               parts=parts,
                               ids=joined_ids)

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            full_path = os.path.join(self.dataset_dir, pcap_file)
            if not os.path.exists(full_path):
                continue
            yield self._make_traffic_sequence(pcap_file, ranges, "unknown")

    def _make_traffic_sequence(self, pcap_file: str, ranges, name_suffix) -> TrafficSequence:
        full_path = os.path.join(self.dataset_dir, pcap_file)
        all_packet_info = read_packet_labels(full_path)
        traffic_type_labels = all_packet_info["traffic_type"]
        ids = ranges_of_list(traffic_type_labels.index.values.tolist(), ranges)
        name = f"{pcap_file}@UNSW-NB15:{name_suffix}"
        packet_reader = SubsetPacketReader(full_path, ranges)
        parts = self._make_parts(all_packet_info)
        return TrafficSequence(name=name, packet_reader=packet_reader, labels=traffic_type_labels, ids=ids, parts=parts)

    def _load_ranges(self):
        path = os.path.join(self.dataset_dir, RANGES_FILE)
        with open(path, "r") as f:
            return json.load(f)

    def _load_subset(self, subset_name: str, ranges):
        if subset_name == "all" or subset_name == "default":
            return {
                "benign": {pcap: r for pcap, r in ranges["benign"].items() if pcap in DEFAULT_BENIGN_PCAPS},
                "unknown": {pcap: r for pcap, r in ranges["unknown"].items() if pcap not in DEFAULT_BENIGN_PCAPS}
            }
        elif subset_name == "tiny":
            return TINY_SUBSET
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
            for pcap in iter_pcaps(self.dataset_dir, skip_not_found=False, yield_relative=True):
                if index in indexes:
                    selected.append(pcap)
                index += 1
        return selected

    def _make_parts(self, labels):
        attacks = labels[labels["traffic_type"] == TrafficType.ATTACK].reset_index()
        attack_parts = attacks.groupby(attacks["attack_type"])["packet_id"].apply(list).to_dict()
        attack_parts = {name: indexes for name, indexes in attack_parts.items() if len(indexes) > 0}
        benign_ids = labels[labels["traffic_type"] == TrafficType.BENIGN].index.values.tolist()
        parts = {
            "all": labels.index.values.tolist(),
        }
        # add part for each attack that consists of all benign traffic plus the traffic of the attack
        parts.update({
            attack_name: attack_ids + benign_ids
            for attack_name, attack_ids in attack_parts.items()
        })
        return parts

    def get_dataset_name(self):
        return "unsw-nb15"

    def get_train_set_name(self):
        return ",".join(sorted(self.subset["benign"].keys()))

    def get_testset_name(self):
        return ",".join(sorted(self.subset["unknown"].keys()))


class UNSWNB15Preprocessor(DatasetPreprocessor):

    def _parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument("--only-ranges", required=False, action="store_true")
        parser.add_argument("--only-stats", action="store_true", help="Only make stats")
        parser.add_argument("--only-validate", action="store_true", help="Only validate")
        parsed = parser.parse_args(args)
        if parsed.only_stats == True and parsed.only_ranges == True:
            raise ValueError("--only-stats and --only-ranges cannot be specified at the same time.")
        return parsed

    def preprocess(self, dataset_path: str, additional_args):
        parsed = self._parse_args(additional_args)
        if parsed.only_ranges == False and parsed.only_stats == False and parsed.only_validate == False:
            label_associator = UNSWNB15LabelAssociator(dataset_path)
            for pcap in iter_pcaps(dataset_path, yield_relative=True):
                logging.info("Make ranges for %s" % pcap)
                full_path = os.path.join(dataset_path, pcap)
                label_associator.associate_pcap_labels(full_path, packet_id_prefix=pcap)

        if parsed.only_stats != True and parsed.only_validate != True:
            ranges = self._make_ranges(dataset_path)
            ranges_path = os.path.join(dataset_path, RANGES_FILE)
            with open(ranges_path, "w") as f:
                json.dump(ranges, f)
        if parsed.only_validate == False:
            self._make_stats(dataset_path)
        self._validate(dataset_path)

    def _make_ranges(self, dataset_path) -> dict:
        ranges = {
            "benign": {},
            "unknown": {}
        }
        index = 0
        for pcap in iter_pcaps(dataset_path, skip_not_found=False, yield_relative=True):
            full_path = os.path.join(dataset_path, pcap)
            if os.path.exists(full_path):
                ranges["benign"][pcap] = self.find_ranges_of_type(full_path, TrafficType.BENIGN)
            else:
                logging.info("%s not found", pcap)
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
        ranges.append([current_start, "end"])
        return ranges

    def _make_stats(self, dataset_path):
        output_file = os.path.join(dataset_path, "attack_stats.csv")
        data = []
        for pcap in iter_pcaps(dataset_path, skip_not_found=True, yield_relative=True):
            logging.info("Make stats for %s" % pcap)
            full_path = os.path.join(dataset_path, pcap)
            labels = read_packet_labels(full_path)
            attacks = labels[labels["traffic_type"] == TrafficType.ATTACK]
            attack_perc = len(attacks) / len(labels)
            pcap_info = attacks.groupby(attacks["attack_type"])["flow_id"].count().to_dict()
            pcap_info.update({
                "pcap": pcap,
                "total": len(labels),
                "num_attacks": len(attacks),
                "fraction_attacks": attack_perc,
            })
            data.append(pcap_info)
        pandas.DataFrame(data).set_index("pcap").to_csv(output_file)

    def _validate(self, dataset_path):
        stats = get_stats(dataset_path)
        column_names = load_column_names(os.path.join(dataset_path, CSV_FOLDER, CSV_FEATURE_NAMES_FILE))
        true_labels = pandas.concat([
            _read_flow_labels_csv(os.path.join(dataset_path, CSV_FOLDER, csv), column_names)
            for csv in CSV_FILES
        ], ignore_index=True)
        for attack in true_labels[FlowCsvColumns.ATTACK_CATEGORY.value].unique():
            if type(attack) is not str:
                continue
            stats_name = attack.strip().lower()
            if stats_name not in stats.columns:
                logging.error("Attack %s is not found in stats!", stats_name)
                continue
            filtered = true_labels[true_labels[FlowCsvColumns.ATTACK_CATEGORY.value] == attack]
            pkts_per_flow = filtered[FlowCsvColumns.SOURCE_PKT_COUNT.value] + filtered[
                FlowCsvColumns.DEST_PKT_COUNT.value]
            true_total_packets = pkts_per_flow.sum()
            stats_packet_count = int(stats[stats_name].sum())
            if stats_packet_count != true_total_packets:
                logging.error("Expected stats to have %s packets of attack %s; but only got %s!", true_total_packets,
                              stats_name, stats_packet_count)


def iter_pcaps(dataset_path: str, skip_not_found=True, yield_relative=False):
    for folder, pcap_files in PCAP_FILES.items():
        for pcap_file in pcap_files:
            relative_path = os.path.join(folder, pcap_file)
            full_path = os.path.join(dataset_path, relative_path)
            if not skip_not_found or os.path.exists(full_path):
                if yield_relative:
                    yield relative_path
                else:
                    yield full_path
            else:
                logging.warning("Cannot find %s; skip", full_path)


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


class UNSWNB15LabelAssociator(PacketLabelAssociator):

    def __init__(self, dataset_path: str):
        super().__init__(["attack_type"])
        self.unrecognized_proto_counter = 0
        self.flow_formatter = pcap_utils.FlowIDFormatter()
        self.attack_flows, self.attack_flow_ids = self._load_attack_flows(dataset_path)

    def get_attack_flows(self, pcap_file):
        # all attack flows are loaded on startup
        return self.attack_flows, self.attack_flow_ids

    def make_flow_ids(self, packet: Packet) -> Tuple[str, str]:
        timestamp, buf = packet
        return self.flow_formatter.make_flow_ids(timestamp, buf, packet_type=dpkt.sll.SLL)

    def output_csv_file(self, pcap_file) -> str:
        return packet_label_file(pcap_file)

    def unpack_additional_info(self, additional_info: AdditionalInfo):
        if type(additional_info) is not str:
            return [""]
        return [additional_info.strip().lower()]

    def date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        epoch_time = cell_content
        return datetime.datetime.utcfromtimestamp(epoch_time)

    def _load_attack_flows(self, dataset_path):
        column_names = load_column_names(os.path.join(dataset_path, CSV_FOLDER, CSV_FEATURE_NAMES_FILE))
        df = pandas.concat([
            _read_flow_labels_csv(os.path.join(dataset_path, CSV_FOLDER, csv), column_names)
            for csv in CSV_FILES
        ], ignore_index=True)
        proto_as_numbers = df[FlowCsvColumns.PROTOCOL.value].apply(self.proto_to_number)
        df[COL_FLOW_ID] = df[FlowCsvColumns.SRC_IP.value] + "-" + df[FlowCsvColumns.DEST_IP.value] + "-" + \
                          df[FlowCsvColumns.SRC_PORT.value].astype(str) + "-" + df[
                              FlowCsvColumns.DEST_PORT.value].astype(
            str) + "-" + proto_as_numbers
        df[COL_REVERSE_FLOW_ID] = df[FlowCsvColumns.DEST_IP.value] + "-" + df[FlowCsvColumns.SRC_IP.value] + "-" + \
                                  df[FlowCsvColumns.DEST_PORT.value].astype(str) + "-" + df[
                                      FlowCsvColumns.SRC_PORT.value].astype(
            str) + "-" + proto_as_numbers
        df[COL_START_TIME] = df[FlowCsvColumns.START_TIME.value]
        df[COL_INFO] = df[FlowCsvColumns.ATTACK_CATEGORY.value]
        self.drop_non_required_cols(df)
        df.set_index(COL_FLOW_ID, inplace=True)
        self._validate_flow_infos(df)
        return self.find_attack_flows(df)

    def proto_to_number(self, p_name):
        """
        Converts the protocol column of the label csv file to an IP protocol number. If the protocol does not rely
        on IP, an empty string is returned. In that case, an ip-based flow cannot be made anyways.
        """
        try:
            return str(socket.getprotobyname(p_name.lower()))
        except:
            if p_name.lower() == "nvp":
                return "11"
            else:
                self.unrecognized_proto_counter += 1
                return ""


def get_stats(dataset_path):
    csv_path = os.path.join(dataset_path, "attack_stats.csv")
    df = pandas.read_csv(csv_path, index_col="pcap")
    return df


def print_stats(dataset_path):
    df = get_stats(dataset_path)
    print(df)


def load_column_names(csv_file):
    df = pandas.read_csv(csv_file, sep=",", encoding="latin1")
    column_names = [row[FEATURE_NAME_COLUMN_FIELD].strip() for _, row in df.iterrows()]
    return column_names


def _read_flow_labels_csv(csv_file, column_names, nrows=None, encoding=None) -> pandas.DataFrame:
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
    df[COL_TRAFFIC_TYPE] = df[FlowCsvColumns.LABEL.value].apply(label_to_traffic_type)
    return df


UNSWNB15 = DatasetUtils(os.path.join("data", "unsw-nb15"), UNSWNB15TrafficReader, UNSWNB15Preprocessor, print_stats)
