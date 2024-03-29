import argparse
import datetime
import itertools
import json
import logging
import math
import os
import pprint
import re
import socket
from enum import Enum
from typing import List

import dpkt
import pandas
import pytz
from pandas import Series

import canids.dataset_utils.packet_label_associator
from canids.dataset_utils.encoding_utils import get_encoding_for_csv
from canids.dataset_utils.packet_label_associator import (
    PacketLabelAssociator,
    COL_FLOW_ID,
    COL_REVERSE_FLOW_ID,
    COL_START_TIME,
    COL_SRC_IP,
    COL_SRC_PKTS,
    COL_DEST_PKTS,
    COL_SRC_PORT,
    COL_END_TIME,
    COL_INFO,
    COL_TRAFFIC_TYPE,
    AdditionalInfo,
    FlowIdentification,
)
from canids.dataset_utils.pcap_utils import SubsetPacketReader
from canids.dataset_utils.reader_utils import ranges_of_list
from canids.dataset_utils.validation_utils import make_report_dict
from canids.types import (
    DatasetPreprocessor,
    TrafficReader,
    TrafficSequence,
    DatasetUtils,
    TrafficType,
    Packet,
)

CSV_FOLDER = "UNSW-NB15 - CSV Files"
CSV_FILES = ["UNSW-NB15_1.csv", "UNSW-NB15_2.csv", "UNSW-NB15_3.csv", "UNSW-NB15_4.csv"]
CSV_FEATURE_NAMES_FILE = "NUSW-NB15_features.csv"
FEATURE_NAME_COLUMN_FIELD = "Name"  # name of the column which specified the feature name in NUSW-NB15_features.csv
PREPROCESSING_REPORT_FILE = "preprocessing_report.json"

PCAP_FILES = {
    "01": [f"{i}.pcap" for i in range(1, 54)],
    "02": [f"{i}.pcap" for i in range(1, 28)],
}

DEFAULT_BENIGN_PCAPS = [os.path.join("01", f) for f in PCAP_FILES["01"][22:27]]

SPECIAL_TRAIN_SUBSETS = {
    "A": [os.path.join("01", f) for f in PCAP_FILES["01"][9:31]],
    "B": [os.path.join("01", f) for f in PCAP_FILES["01"][31:53]],
    "full": [os.path.join("01", f) for f in PCAP_FILES["01"][9:53]],
}
SPECIAL_TEST_SUBSETS = {
    "a": [os.path.join("01", f) for f in PCAP_FILES["01"][0:9]],
    "b": [os.path.join("02", f) for f in PCAP_FILES["02"][0:14]],
    "c": [os.path.join("02", f) for f in PCAP_FILES["02"][14:27]],
}


TINY_SUBSET = {"benign": {"01/1.pcap": [[0, 20]]}, "unknown": {"01/1.pcap": [[21, 30]]}}


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


class UNSWNB15TrafficReader(TrafficReader):
    def __init__(self, directory: str, subset: str):
        super().__init__(directory, subset)
        self.subset = self._load_subset(self.subset_name)

    def read_normal_data(self) -> TrafficSequence:
        traffic_sequences = [
            self._make_traffic_sequence(pcap_file, ranges, "benign")
            for pcap_file, ranges in self.subset["benign"].items()
            if os.path.exists(os.path.join(self.dataset_dir, pcap_file))
        ]
        if len(traffic_sequences) == 1:
            return traffic_sequences[0]
        # if more than one traffic sequences are present, join them into one.
        joined_ids = [
            id_item
            for id_item in itertools.chain(*map(lambda seq: seq.ids, traffic_sequences))
        ]
        joined_labels = Series()
        for traffic_sequence in traffic_sequences:
            joined_labels = joined_labels.append(traffic_sequence.labels)
        joined_reader = itertools.chain(
            *map(lambda seq: seq.packet_reader, traffic_sequences)
        )
        parts = {"all": joined_ids}
        # make sure that the same pcaps, even in different order, result in the same traffic sequence name; regardless
        # of the used test pcaps
        name_identifier = ",".join(
            sorted([t.name.split(".pcap")[0] for t in traffic_sequences])
        )
        return TrafficSequence(
            name=f"benign@UNSW-NB15:%s" % name_identifier,
            labels=joined_labels,
            packet_reader=joined_reader,
            parts=parts,
            ids=joined_ids,
        )

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            full_path = os.path.join(self.dataset_dir, pcap_file)
            if not os.path.exists(full_path):
                continue
            yield self._make_traffic_sequence(pcap_file, ranges, "unknown")

    def _make_traffic_sequence(
        self, pcap_file: str, ranges, name_suffix
    ) -> TrafficSequence:
        full_path = os.path.join(self.dataset_dir, pcap_file)
        all_packet_info = read_packet_labels(full_path)
        traffic_type_labels = all_packet_info["traffic_type"]
        ids = ranges_of_list(traffic_type_labels.index.values.tolist(), ranges)
        name = f"{pcap_file}@UNSW-NB15:{name_suffix}"
        packet_reader = SubsetPacketReader(full_path, ranges)
        parts = self._make_parts(all_packet_info)
        return TrafficSequence(
            name=name,
            packet_reader=packet_reader,
            labels=traffic_type_labels,
            ids=ids,
            parts=parts,
        )

    def _load_subset(self, subset_name: str):
        if subset_name == "all" or subset_name == "default":
            return {
                "benign": {
                    pcap: [[0, "end"]]
                    for pcap in iter_pcaps(self.dataset_dir, skip_not_found=True)
                    if pcap in DEFAULT_BENIGN_PCAPS
                },
                "unknown": {
                    pcap: [[0, "end"]]
                    for pcap in iter_pcaps(self.dataset_dir, skip_not_found=True)
                    if pcap not in DEFAULT_BENIGN_PCAPS
                },
            }
        elif subset_name == "tiny":
            return TINY_SUBSET
        # else: subset name must be of pattern "[test split]/[attack file1],[attack file2],..." or reference
        # a key from the SPECIAL_{TRAIN,TEST}_SUBSETS defined above (e.g. "A/b" for the "A" train set and "b" test set)
        benign, unknown = subset_name.split("/")
        if benign == "" or unknown == "":
            raise ValueError(
                "Invalid subset name '%s': Empty splits are not allowed" % subset_name
            )
        if benign in SPECIAL_TRAIN_SUBSETS:
            benign_pcaps = SPECIAL_TRAIN_SUBSETS[benign]
        else:
            benign_pcaps = self.select_pcaps(benign.split(","))
        if unknown in SPECIAL_TEST_SUBSETS:
            unknown_pcaps = SPECIAL_TEST_SUBSETS[unknown]
        else:
            unknown_pcaps = self.select_pcaps(unknown.split(","))
        return {
            "benign": {pcap: [[0, "end"]] for pcap in benign_pcaps},
            "unknown": {pcap: [[0, "end"]] for pcap in unknown_pcaps},
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
            for pcap in iter_pcaps(
                self.dataset_dir, skip_not_found=False, yield_relative=True
            ):
                if index in indexes:
                    selected.append(pcap)
                index += 1
        return selected

    def _make_parts(self, labels):
        attacks = labels[labels["traffic_type"] == TrafficType.ATTACK].reset_index()
        attack_parts = (
            attacks.groupby(attacks["attack_type"])["packet_id"].apply(list).to_dict()
        )
        attack_parts = {
            name: indexes for name, indexes in attack_parts.items() if len(indexes) > 0
        }
        benign_ids = labels[
            labels["traffic_type"] == TrafficType.BENIGN
        ].index.values.tolist()
        parts = {
            "all": labels.index.values.tolist(),
        }
        # add part for each attack that consists of all benign traffic plus the traffic of the attack
        parts.update(
            {
                attack_name: attack_ids + benign_ids
                for attack_name, attack_ids in attack_parts.items()
            }
        )
        return parts

    def get_dataset_name(self):
        return "unsw-nb15"

    def get_train_set_name(self):
        if "/" not in self.subset_name:
            return self.subset_name
        else:
            return self.subset_name.split("/")[0]

    def get_testset_name(self):
        if "/" not in self.subset_name:
            return self.subset_name
        splitted = self.subset_name.split("/")
        if len(splitted) == 0:
            return ""
        return splitted[1]


class UNSWNB15Preprocessor(DatasetPreprocessor):
    def _parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument("--only-stats", action="store_true", help="Only make stats")
        parser.add_argument(
            "--only-validate", action="store_true", help="Only validate"
        )
        parser.add_argument(
            "--modify-timestamps",
            choices=["none", "ceil", "round"],
            default="none",
            help="Mode Timestamp of packets",
        )
        parser.add_argument(
            "--use-end-time",
            action="store_true",
            help="Use the end time of each flow for determining whether a packet is part of it or not.",
        )
        parsed = parser.parse_args(args)
        return parsed

    def preprocess(self, dataset_path: str, additional_args):
        parsed = self._parse_args(additional_args)
        if parsed.only_stats == False and parsed.only_validate == False:
            label_associator = UNSWNB15LabelAssociator(
                dataset_path,
                use_end_time=parsed.use_end_time
                if parsed.use_end_time is not None
                else False,
                packet_modify_mode=parsed.modify_timestamps,
            )
            for pcap in iter_pcaps(dataset_path, yield_relative=True):
                full_path = os.path.join(dataset_path, pcap)
                label_associator.associate_pcap_labels(full_path, packet_id_prefix=pcap)
            report = {
                "unrecognized_protocols": label_associator.unrecognized_proto_counter,
                "unmatched_packets": label_associator.report.json_serializable(),
            }
            self._write_preprocessing_report(dataset_path, report)
        if not parsed.only_validate:
            logging.info("Make stats...")
            self._make_stats(dataset_path)
        self._validate(dataset_path)

    def _make_stats(self, dataset_path):
        output_file = os.path.join(dataset_path, "attack_stats.csv")
        data = []
        for pcap in iter_pcaps(dataset_path, skip_not_found=True, yield_relative=True):
            logging.info("Make stats for %s" % pcap)
            full_path = os.path.join(dataset_path, pcap)
            labels = read_packet_labels(full_path)
            attacks = labels[labels["traffic_type"] == TrafficType.ATTACK]
            attack_perc = len(attacks) / len(labels)
            pcap_info = (
                attacks.groupby(attacks["attack_type"])["flow_id"].count().to_dict()
            )
            pcap_info.update(
                {
                    "pcap": pcap,
                    "total": len(labels),
                    "num_attacks": len(attacks),
                    "fraction_attacks": attack_perc,
                }
            )
            data.append(pcap_info)
        pandas.DataFrame(data).set_index("pcap").to_csv(output_file)

    def _validate(self, dataset_path, ignore_unrecognized_protocols=True):
        validation_report_path = os.path.join(dataset_path, "validation_report.json")
        stats = get_stats(dataset_path)
        true_labels = load_flows(dataset_path)
        total_expected_packets = 0
        total_actual_packets = 0
        total_expected_flows = 0
        report = {}
        with open(os.path.join(dataset_path, PREPROCESSING_REPORT_FILE), "r") as f:
            preprocessing_report = json.load(f)
        unmatched_protocols = {
            proto
            for proto in preprocessing_report["unrecognized_protocols"].keys()
            if ignore_unrecognized_protocols
        }
        print(unmatched_protocols)
        for attack in true_labels[FlowCsvColumns.ATTACK_CATEGORY.value].unique():
            if type(attack) is not str:
                continue
            stats_name = attack.strip().lower()
            if stats_name not in stats.columns:
                logging.error("Attack %s is not found in stats!", stats_name)
                continue
            filtered = true_labels[
                true_labels[FlowCsvColumns.ATTACK_CATEGORY.value] == attack
            ]
            if ignore_unrecognized_protocols:
                filtered = filtered[
                    ~filtered[FlowCsvColumns.PROTOCOL.value]
                    .str.lower()
                    .str.strip()
                    .isin(unmatched_protocols)
                ]

            expected_flows = len(filtered)
            total_expected_flows += expected_flows
            pkts_per_flow = (
                filtered[FlowCsvColumns.SOURCE_PKT_COUNT.value]
                + filtered[FlowCsvColumns.DEST_PKT_COUNT.value]
            )
            expected_attack_packets = pkts_per_flow.sum()
            actual_attack_packets = int(stats[stats_name].sum())
            total_expected_packets += expected_attack_packets
            total_actual_packets += actual_attack_packets
            difference = expected_attack_packets - actual_attack_packets
            error = abs(difference) / expected_attack_packets

            if actual_attack_packets != expected_attack_packets:
                logging.error(
                    "Expected stats to have %s packets of attack %s; but got %s! (diff=%s, err=%s)",
                    expected_attack_packets,
                    stats_name,
                    actual_attack_packets,
                    abs(actual_attack_packets - expected_attack_packets),
                    error,
                )
            else:
                logging.info(
                    "%s as expected (%s packets)", stats_name, actual_attack_packets
                )
            report[attack] = make_report_dict(
                expected_flows=expected_flows,
                expected_packets=expected_attack_packets,
                actual_packets=actual_attack_packets,
            )
        report["total"] = make_report_dict(
            expected_flows=total_expected_flows,
            expected_packets=total_expected_packets,
            actual_packets=total_actual_packets,
        )
        logging.info(
            "Expected %s attack packet; got %s",
            total_expected_packets,
            total_actual_packets,
        )
        for key, value_list in preprocessing_report["unmatched_packets"].items():
            report[key] = {
                "count": len(value_list),
                "first": value_list[: min(20, len(value_list) - 1)],
            }
        with open(validation_report_path, "w") as f:
            json.dump(report, f)

    def _write_preprocessing_report(self, dataset_path, report):
        report_path = os.path.join(dataset_path, PREPROCESSING_REPORT_FILE)
        with open(report_path, "w") as f:
            json.dump(report, f)


def iter_pcaps(
    dataset_path: str, skip_not_found=True, yield_relative=False, quiet=False
):
    for folder, pcap_files in PCAP_FILES.items():
        for pcap_file in pcap_files:
            relative_path = os.path.join(folder, pcap_file)
            full_path = os.path.join(dataset_path, relative_path)

            if not skip_not_found or os.path.exists(full_path):
                if yield_relative:
                    yield relative_path
                else:
                    yield full_path
            elif not quiet:
                logging.warning("Cannot find %s; skip", full_path)


def read_packet_labels(pcap) -> pandas.DataFrame:
    csv_file = packet_label_file(pcap)
    label_rows = pandas.read_csv(csv_file, sep=",", index_col=0)
    label_rows["traffic_type"] = label_rows["traffic_type"].apply(
        lambda cell: TrafficType(cell)
    )
    return label_rows


def label_to_traffic_type(label):
    if label == 0:
        return TrafficType.BENIGN
    else:
        return TrafficType.ATTACK


def packet_label_file(pcap_file):
    return "%s_packet_labels.csv" % pcap_file


# This dict contains a mapping of protocol names which are used by the dataset
# but not recognized by python's socket.getprotobyname() method
# Besides, the following protocols are used in the dataset, but cannot be mapped
# to an IP protocol number:
#  no attacks: arp (10064 flows), udt (8), rtp (7),
#  all attacks: ip (137), any (411), pri-enc (137), zero (137), isis (137), sccopmce (137), ib (137)
MISSING_PROTOCOL_MAPPINGS = {
    "nvp": 11,
    "sep": 33,
    "ospf": 89,
    "swipe": 53,
    "ipnip": 4,
    "argus": 13,
    "bbn-rcc": 10,
    "st2": 5,
    "dcn": 19,
    "mhrp": 48,
    "ipv6-no": 59,
    "micp": 95,
    "aes-sp3-d": 96,
    "ipx-n-ip": 111,
    "sm": 122,
    "unas": 144,  # unas = "unassigned" and actually is used for all numbers from 144 to 252. When reading the packet in
    # UNSWNB15LabelAssociator below, those numbers are therefore mapped to 144 in _convert_packet_protocol
}


class UNSWNB15LabelAssociator(PacketLabelAssociator):
    def __init__(self, dataset_path: str, packet_modify_mode: str = "none", **kwargs):
        super().__init__(["attack_type"], **kwargs)
        self.unrecognized_proto_counter = {}
        self.flow_formatter = (
            canids.dataset_utils.packet_label_associator.FlowIDFormatter()
        )
        self.flow_formatter.protocol_converter = self._convert_packet_protocol
        self.attack_flows, self.attack_flow_ids = self._load_attack_flows(dataset_path)
        if packet_modify_mode == "ceil":
            self.modify_packet = self._ceil_packet_timestamp
        elif packet_modify_mode == "round":
            self.modify_packet = self._round_packet_timestamp
        elif packet_modify_mode != "none":
            raise ValueError("Unrecognized PacketModifyMode %s." % packet_modify_mode)

    def _get_flows_for_pcap(self, pcap_file):
        # all attack flows are loaded on startup
        return self.attack_flows, self.attack_flow_ids

    def make_flow_ids(self, packet: Packet) -> FlowIdentification:
        timestamp, buf = packet
        flow_ids = self.flow_formatter.make_flow_ids(
            timestamp, buf, packet_type=dpkt.sll.SLL
        )

        return flow_ids

    def output_csv_file(self, pcap_file) -> str:
        return packet_label_file(pcap_file)

    def _unpack_additional_info(self, additional_info: AdditionalInfo):
        if type(additional_info) is not str:
            return [""]
        return [additional_info.strip().lower()]

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        epoch_time = cell_content
        return datetime.datetime.fromtimestamp(epoch_time).astimezone(pytz.utc)

    def _load_attack_flows(self, dataset_path):
        column_names = load_column_names(
            os.path.join(dataset_path, CSV_FOLDER, CSV_FEATURE_NAMES_FILE)
        )
        df = pandas.concat(
            [
                _read_flow_labels_csv(
                    os.path.join(dataset_path, CSV_FOLDER, csv), column_names
                )
                for csv in CSV_FILES
            ],
            ignore_index=True,
        )
        proto_as_numbers = df[FlowCsvColumns.PROTOCOL.value].apply(self.proto_to_number)
        df[COL_FLOW_ID] = (
            df[FlowCsvColumns.SRC_IP.value]
            + "-"
            + df[FlowCsvColumns.DEST_IP.value]
            + "-"
            + df[FlowCsvColumns.SRC_PORT.value].astype(str)
            + "-"
            + df[FlowCsvColumns.DEST_PORT.value].astype(str)
            + "-"
            + proto_as_numbers
        )
        df[COL_REVERSE_FLOW_ID] = (
            df[FlowCsvColumns.DEST_IP.value]
            + "-"
            + df[FlowCsvColumns.SRC_IP.value]
            + "-"
            + df[FlowCsvColumns.DEST_PORT.value].astype(str)
            + "-"
            + df[FlowCsvColumns.SRC_PORT.value].astype(str)
            + "-"
            + proto_as_numbers
        )
        df[COL_START_TIME] = df[FlowCsvColumns.START_TIME.value]
        if self.use_end_time:
            df[COL_END_TIME] = df[FlowCsvColumns.END_TIME.value]
        df[COL_INFO] = df[FlowCsvColumns.ATTACK_CATEGORY.value]
        df[COL_SRC_PORT] = df[FlowCsvColumns.SRC_PORT.value]
        df[COL_SRC_IP] = df[FlowCsvColumns.SRC_IP.value]
        df[COL_SRC_PKTS] = df[FlowCsvColumns.SOURCE_PKT_COUNT.value]
        df[COL_DEST_PKTS] = df[FlowCsvColumns.DEST_PKT_COUNT.value]
        self._drop_non_required_cols(df)
        df.set_index(COL_FLOW_ID, inplace=True)
        self._validate_flow_infos(df)
        return self._find_attack_flows(df)

    def proto_to_number(self, p_name):
        """
        Converts the protocol column of the label csv file to an IP protocol number. If the protocol does not rely
        on IP, an empty string is returned. In that case, an ip-based flow cannot be made anyways.
        """
        try:
            return str(socket.getprotobyname(p_name.lower()))
        except:
            p_name = p_name.lower()
            if p_name in MISSING_PROTOCOL_MAPPINGS:
                return str(MISSING_PROTOCOL_MAPPINGS[p_name])
            else:
                if p_name not in self.unrecognized_proto_counter:
                    self.unrecognized_proto_counter[p_name] = 0
                self.unrecognized_proto_counter[p_name] += 1
                return ""

    def _ceil_packet_timestamp(self, packet) -> Packet:
        ts, buf = packet
        new_ts = math.ceil(ts)
        return new_ts, buf

    def _round_packet_timestamp(self, packet) -> Packet:
        ts, buf = packet
        new_ts = round(ts)
        return new_ts, buf

    def _convert_packet_protocol(self, protocol_number: int):
        # map all protocol number with protocol name "unassigned" to 144, which is used in the flow labels
        if 144 <= protocol_number <= 252:
            return 144
        else:
            return protocol_number


def get_stats(dataset_path):
    csv_path = os.path.join(dataset_path, "attack_stats.csv")
    df = pandas.read_csv(csv_path, index_col="pcap")
    return df


def print_stats(dataset_path):
    attacks_by_prot = analyse_flows(dataset_path)
    pprint.pprint(attacks_by_prot)
    df = get_stats(dataset_path)
    print(df)


def load_column_names(csv_file):
    df = pandas.read_csv(csv_file, sep=",", encoding="latin1")
    column_names = [row[FEATURE_NAME_COLUMN_FIELD].strip() for _, row in df.iterrows()]
    return column_names


def load_flows(dataset_path) -> pandas.DataFrame:
    column_names = load_column_names(
        os.path.join(dataset_path, CSV_FOLDER, CSV_FEATURE_NAMES_FILE)
    )
    true_labels = pandas.concat(
        [
            _read_flow_labels_csv(
                os.path.join(dataset_path, CSV_FOLDER, csv), column_names
            )
            for csv in CSV_FILES
        ],
        ignore_index=True,
    )
    return true_labels


def _read_flow_labels_csv(
    csv_file, column_names, nrows=None, encoding=None
) -> pandas.DataFrame:
    logging.debug("Read flow features from %s", csv_file)
    if encoding is None:
        ip_pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        encoding = get_encoding_for_csv(csv_file, lambda df: ip_pattern.match(df[0][0]))
        if encoding is None:
            logging.warning("Cannot determine encoding for %s; use utf_8", csv_file)
            encoding = "utf_8"
    df = pandas.read_csv(
        csv_file,
        sep=",",
        low_memory=False,
        header=None,
        names=column_names,
        encoding=encoding,
        nrows=nrows,
    )
    df.dropna(
        how="all", inplace=True
    )  # drop all empty rows (some csv are miss-formatted)
    df[COL_TRAFFIC_TYPE] = df[FlowCsvColumns.LABEL.value].apply(label_to_traffic_type)
    df[FlowCsvColumns.ATTACK_CATEGORY.value] = (
        df[FlowCsvColumns.ATTACK_CATEGORY.value].astype(str).str.strip().str.lower()
    )
    # Fix duplicate naming of "backdoors" and "backdoor"; only use "backdoor"
    df[FlowCsvColumns.ATTACK_CATEGORY.value] = df[
        FlowCsvColumns.ATTACK_CATEGORY.value
    ].apply(
        lambda attack_name: "backdoor" if attack_name == "backdoors" else attack_name
    )
    return df


def analyse_flows(dataset_path):
    flow_labels = load_flows(dataset_path)
    flow_labels = flow_labels[flow_labels[COL_TRAFFIC_TYPE] == TrafficType.ATTACK]
    grouped_by = (
        flow_labels[FlowCsvColumns.PROTOCOL.value]
        .groupby(flow_labels[FlowCsvColumns.PROTOCOL.value])
        .count()
    )
    return grouped_by.to_dict()


UNSWNB15 = DatasetUtils(
    os.path.join("data", "unsw-nb15"),
    UNSWNB15TrafficReader,
    UNSWNB15Preprocessor,
    print_stats,
)
