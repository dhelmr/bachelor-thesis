from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from anomaly_detection.one_class_svm import OneClassSVMDE
from anomaly_detection.types import TrafficType, DecisionEngine, TrafficSequence, Preprocessor
import pandas as pd
import numpy as np
import os.path
from anomaly_detection.db import DBConnector
import pickle


class AnomalyDetector:
    def __init__(self, decision_engine: DecisionEngine, preprocessor: Preprocessor):
        self.preprocessor: Preprocessor = preprocessor
        self.decision_engine: DecisionEngine = decision_engine

    def build_profile(self, traffic_data: np.ndarray):
        self.preprocessor.initialize(traffic_data)
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        self.decision_engine.fit(preprocessed)

    def feed_traffic(self, db: DBConnector, classification_id: str, ids: list, traffic_data: np.ndarray, traffic_type=TrafficType.UNKNOWN):
        if len(ids) != len(traffic_data):
            raise ValueError(
                f"Length of ids and traffic data must be equal! len(ids)={len(ids)}, len(traffic_data)={len(traffic_data)}")
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        predictions = self.decision_engine.classify(preprocessed)
        db.save_classifications(classification_id, ids, predictions)

    def serialize(self): 
        return pickle.dumps(self)

    @staticmethod
    def deserialize(s):
        obj = pickle.loads(s)
        if type(obj) is not AnomalyDetector:
            raise ValueError("Invalid type of deserialized object (must be AnomalyDetector)! %s" % str(type(obj)))
        return obj



class StandardPreprocessor(Preprocessor):
    def __init__(self):
        self.normalizer = Pipeline(
            [("minmax", MinMaxScaler()), ("standard", StandardScaler())])

    def initialize(self, traffic_data: np.ndarray):
        self.normalizer.fit(traffic_data)

    def preprocess_data(self, traffic_data: np.ndarray):
        return self.normalizer.transform(traffic_data)

    def get_name(self):
        return "standard_preprocessor"
