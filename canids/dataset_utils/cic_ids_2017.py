import argparse
import os
import re
from enum import Enum

import dpkt
import numpy as np
from pandas import Series

from canids.dataset_utils.packet_label_associator import *
from canids.dataset_utils.pcap_utils import FlowIDFormatter, SubsetPacketReader
from canids.dataset_utils.reader_utils import ranges_of_list
from canids.types import TrafficSequence, TrafficReader, DatasetPreprocessor, DatasetUtils


class PcapFiles(Enum):
    MONDAY = "PCAPs/Monday-WorkingHours.pcap"
    TUESDAY = "PCAPs/Tuesday-WorkingHours.pcap"
    WEDNESDAY = "PCAPs/Wednesday-WorkingHours.pcap"
    THURSDAY = "PCAPs/Thursday-WorkingHours.pcap"
    FRIDAY = "PCAPs/Friday-WorkingHours.pcap"


BENIGN_PCAP_FILE = PcapFiles.MONDAY
TRAFFIC_FILE_PATTERN = re.compile(".*.pcap")

LABEL_COLUMN_NAME = "Label"
PCAPS_SUBDIR = "PCAPs"
BENIGN_LABEL = "BENIGN"

SMALL_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE: [
            (0, 10_000),
            (50_000, 1_500_000),
            (10_000_000, "end")
        ],
    },
    "unknown": {
        PcapFiles.FRIDAY: [
            (400, 5000),
            (50000, 90000),
            (5_000_000, "end")
        ],
        PcapFiles.TUESDAY: [
            (999, 99_999)
        ]
    },
    "test_name": "small",
    "train_name": "small"
}
TINY_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE: [
            (0, 100),
            (400, 1000)
        ],
        PcapFiles.THURSDAY: [
            (0, 400)
        ],
    },
    "unknown": {
        PcapFiles.THURSDAY: [
            (999, 12_000)
        ],
        PcapFiles.WEDNESDAY: [
            (99, 1000),
            (2099, 10_000),
        ]
    },
    "test_name": "tiny",
    "train_name": "tiny"
}

DEFAULT_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE: [(0, "end")]
    },
    "unknown": {pcap_file: [(0, "end")] for pcap_file in PcapFiles if pcap_file is not BENIGN_PCAP_FILE},
    "test_name": "Tuesday, Wednesday, Thursday, Friday",
    "train_name": "Monday"
}
SUBSETS = {
    "default": DEFAULT_SUBSET,
    "small": SMALL_SUBSET,
    "tiny": TINY_SUBSET
}
# create one subset for each attack day (training day is monday)
for pcap_file in PcapFiles:
    if pcap_file is BENIGN_PCAP_FILE:
        continue
    name = pcap_file.name.lower()
    SUBSETS[name] = {
        "benign": {
            BENIGN_PCAP_FILE: [(0, "end")]
        },
        "unknown": {pcap_file: [(0, "end")]},
        "test_name": name,
        "train_name": "Monday"
    }

PCAP_LABEL_FILES = {
    PcapFiles.MONDAY: ["labels/Monday-WorkingHours.pcap_ISCX.csv"],
    PcapFiles.TUESDAY: ["labels/Tuesday-WorkingHours.pcap_ISCX.csv"],
    PcapFiles.WEDNESDAY: ["labels/Wednesday-workingHours.pcap_ISCX.csv"],
    PcapFiles.THURSDAY: ["labels/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                         "labels/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"],
    PcapFiles.FRIDAY: ["labels/Friday-WorkingHours-Morning.pcap_ISCX.csv",
                       "labels/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                       "labels/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                       ]
}
PacketID = str


def read_labels_csv(file, nrows=None):
    df = pandas.read_csv(file, sep=",", low_memory=False, nrows=nrows, index_col="Flow ID", encoding="cp1252")
    # remove spaces from column labels
    df.rename(columns=lambda x: x.strip(), inplace=True)
    df.dropna(how="all", inplace=True)  # drop all empty rows (some csv are miss-formatted)
    df["Label"] = df["Label"].apply(lambda x: x.upper())
    return df


class CIC2017TrafficReader(TrafficReader):

    def __init__(self, directory: str, subset: str):
        super().__init__(directory, subset)
        if subset not in SUBSETS:
            raise ValueError("Subset %s is not valid" % subset)
        self.subset = SUBSETS[subset]

    def read_normal_data(self) -> TrafficSequence:
        traffic_sequences = [self._make_traffic_sequence(pcap_file, ranges) for pcap_file, ranges in
                             self.subset["benign"].items()]
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
        return TrafficSequence(name=f"benign@CIC-IDS-2017:{self.subset_name}",
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               parts=parts,
                               ids=joined_ids)

    def _make_traffic_sequence(self, pcap_file: PcapFiles, ranges) -> TrafficSequence:
        labels = read_packet_labels(self.dataset_dir, pcap_file.value)
        traffic_types = labels["traffic_type"]
        full_pcap_path = os.path.join(self.dataset_dir, pcap_file.value)
        ids = ranges_of_list(labels.index.values.tolist(), ranges)
        name = f"{pcap_file.name}@CIC-IDS-2017:{self.subset_name}"
        packet_reader = SubsetPacketReader(full_pcap_path, ranges)
        parts = self._make_parts(labels)
        return TrafficSequence(name=name, packet_reader=packet_reader, labels=traffic_types, ids=ids, parts=parts)

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            yield self._make_traffic_sequence(pcap_file, ranges)

    def _make_parts(self, labels):
        attacks = labels[labels["traffic_type"] == TrafficType.ATTACK].reset_index()
        attack_parts = attacks.groupby(attacks["attack_type"])["packet_id"].apply(list).to_dict()
        attack_parts = {name: indexes for name, indexes in attack_parts.items() if len(indexes) > 0}
        benigns = labels[labels["traffic_type"] == TrafficType.BENIGN].index.values.tolist()
        parts = {
            "all": labels.index.values.tolist()
        }
        parts.update({
            attack_name: attack_ids + benigns
            for attack_name, attack_ids in attack_parts.items()
        })
        return parts

    def get_dataset_name(self):
        return "cic-ids-2017"

    def get_train_set_name(self):
        return self.subset["train_name"]

    def get_testset_name(self):
        return self.subset["test_name"]


def packet_label_file(dataset_path, pcap_file: str):
    return os.path.join(dataset_path, os.path.basename(pcap_file) + "_packet_labels.csv")


def read_packet_labels(dataset_path, pcap_file: str):
    packet_labels = packet_label_file(dataset_path, pcap_file)
    if not os.path.exists(packet_labels):
        raise FileNotFoundError("Cannot find %s. Did you preprocess the dataset first?" % packet_labels)
    df = pandas.read_csv(packet_labels, index_col="packet_id")
    df["traffic_type"] = df["traffic_type"].map(lambda value: TrafficType(value))
    return df


class CICIDS2017Preprocessor(DatasetPreprocessor):

    def __init__(self):
        self.flow_formatter = FlowIDFormatter()

    def _parse_args(self, args):
        parser = argparse.ArgumentParser()
        parser.add_argument("--only-stats", action="store_true", help="Only make stats")
        parsed = parser.parse_args(args)
        return parsed

    def preprocess(self, dataset_path: str, additional_args=[]):
        parsed = self._parse_args(additional_args)
        if parsed.only_stats != True:
            associator = CICIDS2017LabelAssociator(dataset_path)
            for pcap in PcapFiles:
                full_path = os.path.join(dataset_path, pcap.value)
                associator.associate_pcap_labels(full_path, packet_id_prefix=pcap.value)
        self._make_stats(dataset_path)

    def _make_stats(self, dataset_path):
        output_file = os.path.join(dataset_path, "attack_stats.csv")
        data = []
        for pcap in PcapFiles:
            labels = read_packet_labels(dataset_path, pcap.value)
            attacks = labels[labels["traffic_type"] == TrafficType.ATTACK]
            attack_perc = len(attacks) / len(labels)
            pcap_info = attacks.groupby(attacks["attack_type"])["flow_id"].count().to_dict()
            pcap_info.update({
                "pcap": pcap.value,
                "total": len(labels),
                "num_attacks": len(attacks),
                "fraction_attacks": attack_perc,
            })
            data.append(pcap_info)
        pandas.DataFrame(data).set_index("pcap").to_csv(output_file)


class CICIDS2017LabelAssociator(PacketLabelAssociator):

    def __init__(self, dataset_path):
        super().__init__(["attack_type"])
        self.dataset_path = dataset_path
        self.flow_formatter = FlowIDFormatter()
        # The timestamp format in the csv files does not contain any timezone information
        self.timezone = pytz.timezone("Canada/Atlantic")

    def _get_attack_flows(self, pcap_file):
        relative_path = pcap_file[len(self.dataset_path):]
        if relative_path.startswith(os.path.sep):
            relative_path = relative_path[1:]
        label_files = PCAP_LABEL_FILES[PcapFiles(relative_path)]
        df = pandas.concat([
            read_labels_csv(os.path.join(self.dataset_path, f)) for f in label_files
        ])
        df.dropna(how="all", inplace=True)  # drop all empty rows (some csv are miss-formatted)
        df[COL_REVERSE_FLOW_ID] = df.index.map(lambda flow: self.reverse_flow_id(flow))
        df[COL_TRAFFIC_TYPE], df[COL_INFO] = zip(*df["Label"].apply(self.parse_label_field))
        df[COL_START_TIME] = df["Timestamp"]
        self._drop_non_required_cols(df)
        return self._find_attack_flows(df)

    def reverse_flow_id(self, flow_id: str):
        splitted = flow_id.split("-")
        if len(splitted) != 5:
            return "<invalid flow>"
        src_ip, dest_ip, src_port, dest_port, protocol = splitted
        return self.flow_formatter.format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=True)

    def make_flow_ids(self, packet: Packet) -> Tuple[str, str]:
        timestamp, buf = packet
        return self.flow_formatter.make_flow_ids(timestamp, buf, packet_type=dpkt.ethernet.Ethernet)

    def output_csv_file(self, pcap_file) -> str:
        return packet_label_file(self.dataset_path, pcap_file)

    def _unpack_additional_info(self, additional_info: AdditionalInfo) -> List[str]:
        if type(additional_info) is not str:
            return [""]
        return [additional_info.strip().lower()]

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        # the date is java-style formatted
        date_part, time_part = cell_content.split(" ")
        d, m, y = date_part.split("/")
        if len(d) != 2:
            d = "0" + d
        if len(m) != 2:
            m = "0" + m
        date_part = f"{d}/{m}/{y}"
        if time_part[1] == ":":
            time_part = "0" + time_part
        if time_part.count(":") == 1:
            time_part += ":00"
        datestr = f"{date_part} {time_part}"
        parsed_date = datetime.datetime.strptime(datestr,
                                                 "%d/%m/%Y %I:%M:%S")  # example "5/7/2017 8:42" = 5th of July 2017
        with_tz = self.timezone.localize(parsed_date, is_dst=None)
        return with_tz

    def parse_label_field(self, label: str) -> Tuple[TrafficType, AdditionalInfo]:
        if label == BENIGN_LABEL:
            return TrafficType.BENIGN, None
        else:
            return TrafficType.ATTACK, label


def get_stats(dataset_path):
    csv_path = os.path.join(dataset_path, "attack_stats.csv")
    df = pandas.read_csv(csv_path, index_col="pcap")
    return df


def print_stats(dataset_path):
    df = get_stats(dataset_path)
    with pandas.option_context('float_format', '{:10.0f}'.format):
        df["fraction_attacks"] = df["fraction_attacks"].apply(lambda frac: f"{(frac * 100):3.3f}%")
        print(df.T.replace(np.nan, '0', regex=True))


CICIDS2017 = DatasetUtils(os.path.join("data", "cic-ids-2017"), CIC2017TrafficReader, CICIDS2017Preprocessor,
                          print_stats)
