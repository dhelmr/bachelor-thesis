import pickle
import typing as t

import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficType, DecisionEngine, Preprocessor


class AnomalyDetectorModel:
    def __init__(self, decision_engine: DecisionEngine, preprocessors: t.Sequence[Preprocessor]):
        self.preprocessors: t.Sequence[Preprocessor] = preprocessors
        self.decision_engine: DecisionEngine = decision_engine

    def build_profile(self, traffic_data: np.ndarray):
        self._fit_preprocessors(traffic_data)
        preprocessed = self._transform_with_preprocessors(traffic_data)
        self.decision_engine.fit(preprocessed)

    def feed_traffic(self, db: DBConnector, classification_id: str, ids: list, traffic_data: np.ndarray,
                     traffic_type=TrafficType.UNKNOWN):
        if len(ids) != len(traffic_data):
            raise ValueError(
                f"Length of ids and traffic data must be equal! len(ids)={len(ids)}, len(traffic_data)={len(traffic_data)}")
        preprocessed = self._transform_with_preprocessors(traffic_data)
        predictions = self.decision_engine.classify(preprocessed)
        db.save_classifications(classification_id, ids, predictions)

    def _fit_preprocessors(self, traffic_data: np.ndarray):
        for p in self.preprocessors:
            p.fit(traffic_data)

    def _transform_with_preprocessors(self, traffic_data: np.ndarray):
        transformed = traffic_data
        for p in self.preprocessors:
            transformed = p.transform(traffic_data)
        return transformed

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(s):
        obj = pickle.loads(s)
        if type(obj) is not AnomalyDetectorModel:
            raise ValueError("Invalid type of deserialized object (must be AnomalyDetector)! %s" % str(type(obj)))
        return obj


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
