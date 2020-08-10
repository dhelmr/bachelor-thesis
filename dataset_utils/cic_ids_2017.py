import itertools
import logging
import os
import re
import socket
import typing as t
from datetime import datetime
from enum import Enum

import dpkt as dpkt
import pandas
from pandas import Series

from anomaly_detection.types import TrafficType, TrafficSequence, TrafficReader, DatasetPreprocessor
from dataset_utils import pcap_utils


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
            (999, 99_999)
        ],
        PcapFiles.WEDNESDAY: [
            (1_000_001, 1_000_004),
            (2_000_001, 2_010_004),
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
            raise ValueError("Subet %s is not valid" % subset)
        self.subset = SUBSETS[subset]

    def read_traffic_labels(self, pcap_file: str) -> pandas.Series:
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
            joined_labels = joined_labels.append(traffic_sequence.labels)
        joined_reader = itertools.chain(*map(lambda seq: seq.packet_reader, traffic_sequences))
        return TrafficSequence(name=f"benign@CIC-IDS-2017:{self.subset_name}",
                               labels=joined_labels,
                               packet_reader=joined_reader,
                               ids=joined_ids)

    def _make_traffic_sequence(self, pcap_file: PcapFiles, ranges) -> TrafficSequence:
        full_pcap_path = os.path.join(self.dataset_dir, pcap_file.value)
        labels = self.read_traffic_labels(full_pcap_path)
        ids = self._ranges_of_list(labels.index.values.tolist(), ranges)
        name = f"{pcap_file.name}@CIC-IDS-2017:{self.subset_name}"
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


def make_flow_ids(ts, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    if type(eth.data) is not dpkt.ip.IP:
        return None
    src_ip = socket.inet_ntoa(eth.ip.src)
    dest_ip = socket.inet_ntoa(eth.ip.dst)
    if type(eth.ip.data) is dpkt.tcp.TCP:
        src_port = int(eth.ip.tcp.sport)
        dest_port = int(eth.ip.tcp.dport)
        protocol = 6
    elif type(eth.ip.data) is dpkt.udp.UDP:
        src_port = int(eth.ip.udp.sport)
        dest_port = int(eth.ip.udp.dport)
        protocol = 17
    else:
        src_port = 0
        dest_port = 0
        protocol = 0
    return [format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol),
            format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=False)]


def format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=False):
    if not reverse:
        return "%s-%s-%s-%s-%s" % (src_ip, dest_ip, src_port, dest_port, protocol)
    return "%s-%s-%s-%s-%s" % (dest_ip, src_ip, dest_port, src_port, protocol)


def get_packet_id(timestamp, buf, flow_ids: t.List[str] = None) -> PacketID:
    if flow_ids is None:
        flow_ids = make_flow_ids(timestamp, buf)
    if flow_ids is None:
        return "<no-ip>-%s" % timestamp
    else:
        return "%s-%s" % (flow_ids[0], timestamp)


class CICIDS2017Preprocessor(DatasetPreprocessor):

    def preprocess(self, dataset_path: str):
        for pcap_file, label_files in self.get_abs_paths(dataset_path).items():
            attacks_packet_ids = self.get_attacks_packet_ids(label_files)
            labels = self.generate_labels(pcap_file, attacks_packet_ids)
            df = pandas.DataFrame.from_records(labels, columns=["packet_id", "label"])
            output_csv_path = os.path.join(dataset_path, os.path.basename(pcap_file) + "_packet_labels.csv")
            logging.info("Write packet labels into %s", output_csv_path)
            df.to_csv(output_csv_path, index=False)

    def generate_labels(self, pcap_file: str, attack_times: pandas.DataFrame) \
            -> t.List[t.Tuple[PacketID, TrafficType]]:
        logging.info("Process file %s", pcap_file)
        packets = pcap_utils.read_pcap_pcapng(pcap_file)
        labelled_packets: t.List[t.Tuple[PacketID, TrafficType]] = list()
        progress = 0
        for timestamp, buf in packets:
            flow_ids = make_flow_ids(timestamp, buf)
            packet_id = get_packet_id(timestamp, buf, flow_ids)
            packet_id = "%s_%s" % (progress, packet_id)  # TODO hack to make the packet ids unique
            if (flow_ids is None) or \
                    not (flow_ids[0] in attack_times.index or flow_ids[1] in attack_times.index):
                traffic_type = TrafficType.BENIGN
            else:
                # check for attack times
                traffic_type = TrafficType.ATTACK
            entry = (packet_id, traffic_type.value)
            labelled_packets.append(entry)
            if progress % 50000 == 0:
                logging.info("%s: Processed %s packets...", pcap_file, progress)
            progress += 1
        return labelled_packets

    def get_attacks_packet_ids(self, flow_files: t.List[str]) -> pandas.DataFrame:
        # read in all label csv files and concatenate them
        df = pandas.DataFrame()
        for flow_file in flow_files:
            logging.info("Read labels from %s", flow_file)
            df_part = read_labels_csv(flow_file)
            df = df.append(df_part)
        attacks = df.loc[df["Label"] != BENIGN_LABEL]
        benigns = df.loc[df["Label"] == BENIGN_LABEL]
        attacks["reverse_flow_id"] = attacks.index.map(lambda flow: self.reverse_flow_id(flow))
        in_both = pandas.merge(attacks, benigns, how="inner", left_index=True, right_index=True)
        in_both_reversed_id = pandas.merge(attacks, benigns, how="inner", left_on="reverse_flow_id", right_index=True)
        in_both = pandas.concat([in_both, in_both_reversed_id])
        benign_times = in_both["Timestamp_y"].groupby(in_both.index).apply(
            lambda elements: [self.date_to_timestamp(formatted_date) for formatted_date in list(elements)]
        )
        attack_times = attacks["Timestamp"].groupby(attacks.index).apply(
            lambda elements: [self.date_to_timestamp(formatted_date) for formatted_date in list(elements)]
        )
        result_df = pandas.merge(attack_times, benign_times, how="left", right_index=True, left_index=True)
        result_df.rename(columns={"Timestamp_y": "benign", "Timestamp": "attack"}, inplace=True)
        return result_df

    def get_abs_paths(self, dataset_path: str) -> t.Dict[str, t.List[str]]:
        absolute_paths = dict()
        for pcap_file, label_files in PCAP_LABEL_FILES.items():
            abs_pcap = os.path.join(dataset_path, pcap_file.value)
            abs_label_files = [os.path.join(dataset_path, label_file) for label_file in label_files]
            absolute_paths[abs_pcap] = abs_label_files
        return absolute_paths

    @staticmethod
    def reverse_flow_id(flow_id: str):
        splitted = flow_id.split("-")
        if len(splitted) != 5:
            return "<invalid flow>"
        src_ip, dest_ip, src_port, dest_port, protocol = splitted
        return format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=True)

    def date_to_timestamp(self, datestr: str):
        date_part, time_part = datestr.split(" ")
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
