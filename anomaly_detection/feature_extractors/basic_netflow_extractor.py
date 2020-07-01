import typing as t

import numpy as np

from anomaly_detection.types import FeatureExtractor, TrafficType, PacketReader


class BasicNetflowFeatureExtractor(FeatureExtractor):

    def fit_extract(self, packet_reader: PacketReader) -> np.ndarray:
        # there is no need to do anything here, the features will be extracted statically for each netflow,
        # i.e. disregarding the other traffic records
        return self.extract_features(packet_reader)

    def extract_features(self, packet_reader: PacketReader) -> np.ndarray:
        # TODO
        print("hi")
        return np.zeros((1, 1))  # TODO

    def map_backwards(self, packet_reader: PacketReader, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        pass

    def get_name(self) -> str:
        return "basic_netflow_extractor"
