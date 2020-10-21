import itertools
import os
import re
from datetime import datetime
from enum import Enum

import dpkt
from pandas import Series

from anomaly_detection.types import TrafficSequence, TrafficReader, DatasetPreprocessor, DatasetUtils
from dataset_utils.PacketLabelAssociator import *
from dataset_utils.pcap_utils import FlowIDFormatter, SubsetPacketReader
from dataset_utils.reader_utils import ranges_of_list


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
    }
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
    }
}

DEFAULT_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE: [(0, "end")]
    },
    "unknown": {pcap_file: [(0, "end")] for pcap_file in PcapFiles if pcap_file is not BENIGN_PCAP_FILE}
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
    SUBSETS[pcap_file.name.lower()] = {
        "benign": {
            BENIGN_PCAP_FILE: [(0, "end")]
        },
        "unknown": {pcap_file: [(0, "end")]}
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

PROTOCOL_ENCODINGS = {  # used in csv files
    "udp": 17,
    "tcp": 6,
    "unknown": 0
}


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

    def read_traffic_labels(self, pcap_file: str) -> pandas.Series:
        packet_labels = packet_label_file(self.dataset_dir, pcap_file)
        if not os.path.exists(packet_labels):
            raise FileNotFoundError("Cannot find %s. Did you preprocess the dataset first?" % packet_labels)
        df = pandas.read_csv(packet_labels, index_col="packet_id")
        df["label"] = df["label"].map(lambda value: TrafficType(value))
        return df["label"]

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
        return TrafficSequence(name=f"benign@CIC-IDS-2017:{self.subset_name}",
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               ids=joined_ids)

    def _make_traffic_sequence(self, pcap_file: PcapFiles, ranges) -> TrafficSequence:
        full_pcap_path = os.path.join(self.dataset_dir, pcap_file.value)
        labels = self.read_traffic_labels(full_pcap_path)
        ids = ranges_of_list(labels.index.values.tolist(), ranges)
        name = f"{pcap_file.name}@CIC-IDS-2017:{self.subset_name}"
        packet_reader = SubsetPacketReader(full_pcap_path, ranges)
        return TrafficSequence(name=name, packet_reader=packet_reader, labels=labels, ids=ids)

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            yield self._make_traffic_sequence(pcap_file, ranges)


def packet_label_file(dataset_path, pcap_file):
    return os.path.join(dataset_path, os.path.basename(pcap_file) + "_packet_labels.csv")


class CICIDS2017Preprocessor(DatasetPreprocessor):

    def __init__(self):
        self.flow_formatter = FlowIDFormatter()

    def preprocess(self, dataset_path: str):
        associator = CICIDS2017LabelAssociator(dataset_path)
        for pcap in PcapFiles:
            full_path = os.path.join(dataset_path, pcap.value)
            associator.associate_pcap_labels(full_path)


class CICIDS2017LabelAssociator(PacketLabelAssociator):

    def __init__(self, dataset_path):
        super().__init__([*DEFAULT_HEADER, "attack_type"])
        self.dataset_path = dataset_path
        self.flow_formatter = FlowIDFormatter()

    def get_attack_flows(self, pcap_file):
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
        self.drop_non_required_cols(df)
        return self.find_attack_flows(df)

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

    def write_csv_row(self, csv_writer, packet_id, traffic_type, additional_info):
        if additional_info is None:
            attack_type = ""
        else:
            attack_type = str(additional_info).strip().lower()
        csv_writer.writerow([packet_id, traffic_type.value, attack_type])

    def date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
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
        datestr = f"{date_part} {time_part}"
        result = datetime.strptime(datestr, "%d/%m/%Y %I:%M")  # example "5/7/2017 8:42" = 5th of July 2017
        return result

    def parse_label_field(self, label: str) -> Tuple[TrafficType, AdditionalInfo]:
        if label == BENIGN_LABEL:
            return TrafficType.BENIGN, None
        else:
            return TrafficType.ATTACK, label


CICIDS2017 = DatasetUtils(os.path.join("data", "cic-ids-2017"), CIC2017TrafficReader, CICIDS2017Preprocessor)
