import logging
import os
import re

import pandas

from anomaly_detection.types import TrafficType, TrafficSequence, TrafficReader

BENIGN_DATA_FILE = "Monday-WorkingHours.pcap"
TRAFFIC_FILE_PATTERN = re.compile(".*.pcap")

LABEL_COLUMN_NAME = "Label"
PCAPS_SUBDIR = "PCAPs"
BENIGN_LABEL = "BENIGN"


def read_csv(file, nrows=None):
    df = pandas.read_csv(file, sep=",", low_memory=False, nrows=nrows, index_col="Flow ID", encoding="cp1252")
    # remove spaces from column labels
    df.rename(columns=lambda x: x.strip(), inplace=True)
    df["Label"] = df["Label"].apply(lambda x: x.upper())
    return df


def preprocess(df: pandas.DataFrame, id_prefix: str):
    # TODO these columns include Infinity values, handle
    df.drop(df.columns[[14, 15]], axis=1, inplace=True)
    uuids = [id_prefix + "_" + str(i) for i in range(len(df))]
    df.insert(0, "id", uuids)
    df.set_index("id", inplace=True)


def label_to_traffic_type(label_text: str):
    if BENIGN_LABEL == label_text.upper():
        return TrafficType.BENIGN
    else:
        return TrafficType.ATTACK


def load_label_csv(pcap_file: str):
    csv_file = os.path.basename(pcap_file) + "_ISCX.csv"
    csv_path = os.path.join(os.path.dirname(pcap_file), "..", "labels", csv_file)
    return read_csv(csv_path)


def get_csv_timestamp(timestamp: int):
    # dt.datetime.fromtimestamp(timestamp)
    pass


class CIC2017TrafficReader(TrafficReader):
    def __init__(self, directory: str, number_of_records=None):
        self.pcap_directory = os.path.join(directory, "PCAPs")
        self.pcap_file_iterator = iter(os.listdir(self.pcap_directory))
        self.number_of_records = number_of_records
        self.dataset_dir = directory

    def get_traffic_labels(self, pcap_file: str) -> pandas.Series:
        i = 0
        packet_labels = os.path.join(self.dataset_dir, os.path.basename(pcap_file) + "_packet_labels.csv")
        if not os.path.exists(packet_labels):
            raise FileNotFoundError("Cannot find %s. Did you preprocess the dataset first?" % packet_labels)
        df = pandas.read_csv(packet_labels, index_col="packet_id")
        df["label"] = df["label"].map(lambda value: TrafficType(value))
        return df["label"]

    def read_normal_data(self) -> TrafficSequence:
        return self.make_traffic_sequence(BENIGN_DATA_FILE)

    def make_traffic_sequence(self, pcap_file) -> TrafficSequence:
        full_pcap_path = os.path.join(self.pcap_directory, pcap_file)
        labels = self.get_traffic_labels(full_pcap_path)
        ids = labels.index.values.tolist()
        name = os.path.basename(full_pcap_path)
        return TrafficSequence(name=name, pcap_file=full_pcap_path, labels=labels, ids=ids)

    def __iter__(self):
        return self

    def __next__(self):
        file = next(self.pcap_file_iterator)
        if BENIGN_DATA_FILE == file:
            logging.debug(
                "Skip file %s - it contains only normal traffic.", file)
            return self.__next__()
        if not TRAFFIC_FILE_PATTERN.match(file):
            logging.debug("Skip file %s - does not match pattern. %s", file, TRAFFIC_FILE_PATTERN)
            return self.__next__()

        logging.debug("Load data for file %s", file)
        traffic_sequence = self.make_traffic_sequence(file)
        return traffic_sequence
