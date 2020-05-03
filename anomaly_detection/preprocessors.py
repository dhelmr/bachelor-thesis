import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from anomaly_detection.types import Preprocessor


class StandardScalerPreprocessor(Preprocessor):
    def __init__(self):
        self.scaler = StandardScaler()

    def fit(self, traffic_data: np.ndarray):
        self.scaler.fit(traffic_data)

    def transform(self, traffic_data: np.ndarray):
        return self.scaler.transform(traffic_data)

    def get_name(self):
        return "standard_scaler"


class MinxMaxScalerPreprocessor(Preprocessor):
    def __init__(self):
        self.scaler = MinMaxScaler()

    def fit(self, traffic_data: np.ndarray):
        self.scaler.fit(traffic_data)

    def transform(self, traffic_data: np.ndarray):
        return self.scaler.transform(traffic_data)

    def get_name(self) -> str:
        return "minmax_scaler"
