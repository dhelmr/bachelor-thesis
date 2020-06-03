import typing as t

import numpy as np

from anomaly_detection.types import FeatureExtractor, TrafficType


class BasicNetflowFeatureExtractor(FeatureExtractor):

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        # there is no need to do anything here, the features will be extracted statically for each netflow,
        # i.e. disregarding the other traffic records
        return self.extract_features(pcap_file)

    def extract_features(self, pcap_file: str) -> np.ndarray:
        # TODO
        print("hi")
        return np.zeros((1, 1))  # TODO

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        pass
