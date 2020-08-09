import itertools
import os
import re

import pandas
from pandas import Series

from anomaly_detection.types import TrafficType, TrafficSequence, TrafficReader
from dataset_utils import pcap_utils
from dataset_utils.preprocess_ids2017 import PcapFiles

BENIGN_PCAP_FILE = PcapFiles.MONDAY
TRAFFIC_FILE_PATTERN = re.compile(".*.pcap")

LABEL_COLUMN_NAME = "Label"
PCAPS_SUBDIR = "PCAPs"
BENIGN_LABEL = "BENIGN"

SMALL_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE.value: [
            (0, 10_000),
            (50_000, 1_500_000),
            (10_000_000, "end")
        ],
    },
    "unknown": {
        PcapFiles.FRIDAY.value: [
            (400, 5000),
            (50000, 90000),
            (5_000_000, "end")
        ],
        PcapFiles.TUESDAY.value: [
            (999, 99_999)
        ]
    }
}
TINY_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE.value: [
            (0, 100),
            (400, 1000)
        ],
        PcapFiles.THURSDAY.value: [
            (0, 400)
        ],
    },
    "unknown": {
        PcapFiles.THURSDAY.value: [
            (999, 99_999)
        ],
        PcapFiles.WEDNESDAY.value: [
            (1_000_001, 1_000_004),
            (2_000_001, 2_010_004),
        ]
    }
}

DEFAULT_SUBSET = {
    "benign": {
        BENIGN_PCAP_FILE.value: [(0, "end")]
    },
    "unknown": {pcap_file.value: [(0, "end")] for pcap_file in PcapFiles if pcap_file is not BENIGN_PCAP_FILE}
}
SUBSETS = {
    "default": DEFAULT_SUBSET,
    "small": SMALL_SUBSET,
    "tiny": TINY_SUBSET
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
            raise ValueError("Subet %s is not valid" % subset)
        self.subset = SUBSETS[subset]

    def get_traffic_labels(self, pcap_file: str) -> pandas.Series:
        packet_labels = os.path.join(self.dataset_dir, os.path.basename(pcap_file) + "_packet_labels.csv")
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
            joined_labels = joined_labels.join(traffic_sequence.labels)
        joined_reader = itertools.chain(*map(lambda seq: seq.packet_reader, traffic_sequences))
        return TrafficSequence(name=f"normal@{self.subset_name}",
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               ids=joined_ids)

    def _make_traffic_sequence(self, pcap_file: str, ranges) -> TrafficSequence:
        full_pcap_path = os.path.join(self.dataset_dir, pcap_file)
        labels = self.get_traffic_labels(full_pcap_path)
        ids = self._ranges_of_list(labels.index.values.tolist(), ranges)
        name = os.path.basename(full_pcap_path)
        packet_reader = SubsetPacketReader(full_pcap_path, ranges)
        return TrafficSequence(name=name, packet_reader=packet_reader, labels=labels, ids=ids)

    def __iter__(self):
        for pcap_file, ranges in self.subset["unknown"].items():
            yield self._make_traffic_sequence(pcap_file, ranges)

    def _ranges_of_list(self, input_list, ranges):
        output_list = []
        for start, end in ranges:
            if end == "end":
                output_list += input_list[start:]
            else:
                output_list += input_list[start:end]
        return output_list


class SubsetPacketReader:
    def __init__(self, pcap_path: str, ranges):
        self.pcap_path = pcap_path
        self.ranges = ranges

    def __iter__(self):
        reader = pcap_utils.read_pcap_pcapng(self.pcap_path)
        i = -1
        range_index = 0
        start, end = self.ranges[range_index]
        for packet in reader:
            i += 1
            if i < start:
                continue
            if end != "end" and i >= end:
                range_index += 1
                if len(self.ranges) <= range_index:
                    break
                start, end = self.ranges[range_index]
                continue
            yield packet
