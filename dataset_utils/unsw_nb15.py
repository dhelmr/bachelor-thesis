import logging
import os
import re
from enum import Enum

import pandas

from anomaly_detection.types import DatasetPreprocessor, TrafficReader, TrafficSequence, DatasetUtils
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
        flow_features.set_index("flow_id")

        for pcap in self._iter_pcaps(dataset_path):
            self._generate_pcap_labels(pcap, flow_features)

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
        # make flow ids
        df["flow_id"] = df[FlowCsvColumns.SRC_IP.value] + "-" + df[FlowCsvColumns.DEST_IP.value] + "-" + \
                        df[FlowCsvColumns.SRC_PORT.value].astype(str) + "-" + df[FlowCsvColumns.DEST_PORT.value].astype(
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

    def _generate_pcap_labels(self, pcap_file, flow_features):
        reader = pcap_utils.read_pcap_pcapng(pcap_file, print_progress_after=100)
        for ts, buf in reader:
            ids = self.flow_formatter.make_flow_ids(ts, buf)
            if ids is None:
                packet_id = "%s-<no_ip>" % ts
            else:
                flow_id, reverse_id = ids
                packet_id = "%s-%s" % (flow_id, ts)
                potential_flows = flow_features


UNSWNB15 = DatasetUtils(UNSWNB15TrafficReader, UNSWNB15Preprocessor)
