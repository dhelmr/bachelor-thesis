import argparse
import typing as t

import numpy as np
import pandas

from anomaly_detection.types import TrafficSequence, FeatureExtractor, TrafficType, TrafficReader, DatasetPreprocessor, \
    DatasetUtils


class TestingFeatureExtractor(FeatureExtractor):

    def get_name(self) -> str:
        return "test_extractor"

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        features = []
        for packet in traffic.packet_reader:
            features.append([1, 1])
            features.append([0, 1])
            features.append([1, 0])
            features.append([0, 0])
        return np.array(features)

    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        features = []
        for i in range(len(traffic.ids)):
            if i % 3 == 0:
                features.append([-100, -200])
            else:
                features.append([1, 1])
        return np.array(features)

    def map_backwards(self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        return de_result

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        pass

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return TestingFeatureExtractor()


class DummyTrafficGenerator(TrafficReader):

    def __init__(self, directory: str, subset: str, *args, **kwargs):
        super().__init__(directory, subset)

    def read_normal_data(self) -> TrafficSequence:
        length = 3000
        ids = [str(i) for i in range(length)]
        labels = pandas.Series(data=[TrafficType.BENIGN for i in range(length)], index=ids)
        return TrafficSequence(
            name="Dummy Traffic / Training set",
            packet_reader=DummyPacketReader(length),
            ids=ids,
            labels=labels
        )

    def __next__(self) -> TrafficSequence:
        pass

    def __iter__(self):
        for i in range(10):
            traffic = self._make_dummy_traffic("Dummy traffic / Testset #%s" % i, 1000, i * 100)
            yield traffic

    def _make_dummy_traffic(self, name, length: int, benign_count: int):
        ids = [name + str(i) for i in range(length)]
        label_data = [TrafficType.BENIGN for i in range(benign_count)] + [
            TrafficType.ATTACK for i in range(length - benign_count)]
        labels = pandas.Series(data=label_data, index=ids)
        return TrafficSequence(
            name=name + "(benign: %s/%s)" % (benign_count, length),
            packet_reader=DummyPacketReader(length),
            ids=ids,
            labels=labels
        )


class DummyPacketReader:
    def __init__(self, length: int):
        self.length = length

    def __iter__(self):
        for i in range(self.length):
            yield 420, bytes(42)


class DummyPreprocessor(DatasetPreprocessor):
    def __init__(self, *args, **kwargs):
        pass

    def preprocess(self, **kwargs):
        pass


DummyDataset = DatasetUtils("", DummyPacketReader, DummyPreprocessor, lambda x: None)
