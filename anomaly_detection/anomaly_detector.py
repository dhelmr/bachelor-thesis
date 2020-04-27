from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from anomaly_detection.one_class_svm import OneClassSVMDE
from anomaly_detection.traffic_type import TrafficType
import pandas as pd
import os.path
from typing import Sequence
from abc import ABC, abstractmethod

class AnomalyDetector:
    def __init__(self, log_path, decision_engine):
        self.preprocessor = Preprocessor()
        self.decision_engine = decision_engine
        self.prediction_log = PredictionLog(log_path)

    def build_profile(self, traffic_data):
        self.preprocessor.initialize(traffic_data)
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        self.decision_engine.fit(preprocessed)

    def feed_traffic(self, ids, traffic_data, traffic_type=TrafficType.UNKNOWN):
        if len(ids) != len(traffic_data):
            raise ValueError(f"Length of ids and traffic data must be equal! len(ids)={len(ids)}, len(traffic_data)={len(traffic_data)}")
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        predictions = self.decision_engine.classify(preprocessed)
        self.prediction_log.save(ids, predictions)
        

class PredictionLog:
    def __init__(self, destination_path: str):
        self.destination_path: str = destination_path
        self.columns = ['id', 'label']
        if not os.path.exists(self.destination_path):
            header_df = pd.DataFrame([], columns = self.columns)
            header_df.to_csv(self.destination_path, mode='w', index=False)

    def save(self, ids: list, predictions: Sequence[TrafficType]):
        prediction_values = [p.value for p in predictions]
        data = list(zip(ids, prediction_values))
        df = pd.DataFrame(data, columns = self.columns) 
        df.to_csv(self.destination_path, mode='a', header=False, index=False)

    def read(self):
        df = pd.read_csv(self.destination_path, index_col="id")
        #traffic_types = df["label"].map(lambda x: TrafficType(x))
        return df 
    
class Preprocessor:
    def __init__(self):
        self.normalizer = Pipeline([("minmax", MinMaxScaler()), ("standard", StandardScaler())])
        
    def initialize(self, traffic_data):
        self.normalizer.fit(traffic_data)

    def preprocess_data(self, traffic_data):
        return self.normalizer.transform(traffic_data)