import pandas
import os
import numpy as np
import uuid
from anomaly_detection.traffic_type import TrafficType
from collections import namedtuple

BENIGN_DATA_FILE = "Monday-WorkingHours.pcap_ISCX.csv"
LABEL_COLUMN_NAME = "Label"

def read_csv(file, nrows=None):
    df = pandas.read_csv(file, sep=",", low_memory=False, nrows=nrows)
    # remove spaces from column labels
    df.rename(columns=lambda x: x.strip(), inplace=True)
    return df


def preprocess(df: pandas.DataFrame, id_prefix):
    # TODO these columns include Infinity values, handle
    df.drop(df.columns[[14, 15]], axis=1, inplace=True)
    uuids = [id_prefix+"_"+str(i) for i in range(len(df))]
    df.insert(0, "id", uuids)
    df.set_index("id", inplace=True)

def label_to_traffic_type(label_text: str):
    if "BENIGN" == label_text.upper():
        return TrafficType.BENIGN
    else:
        return TrafficType.ATTACK

TrafficSequence = namedtuple("TrafficSequence", "name traffic labels")

class Reader:
    def __init__(self, directory, number_of_records=None):
        self.directory = directory
        self.file_iterator = iter(os.listdir(directory))
        self.number_of_records = number_of_records

    def split_labels(self, df: pandas.DataFrame):
        labels = df[LABEL_COLUMN_NAME]
        traffic_types = labels.map(label_to_traffic_type)
        without_labels = df.drop(LABEL_COLUMN_NAME, 1)
        return (without_labels, traffic_types)
    
    def read_normal_data(self):
        benign_data = read_csv(os.path.join(
            self.directory, BENIGN_DATA_FILE), nrows=self.number_of_records)
        preprocess(df=benign_data, id_prefix=BENIGN_DATA_FILE)
        without_labels, labels = self.split_labels(benign_data)
        return TrafficSequence(name=BENIGN_DATA_FILE, traffic=without_labels, labels = labels)

    def __iter__(self):
        return self
    
    def __next__(self):
        file = next(self.file_iterator)
        if BENIGN_DATA_FILE == file:
            return self.__next__()
        df = read_csv(os.path.join(self.directory, file),
                      nrows=self.number_of_records)
        preprocess(df, id_prefix=file)
        without_labels, labels = self.split_labels(df)
        return TrafficSequence(name=file, traffic=without_labels, labels = labels)
        
