from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.pipeline import Pipeline
from anomaly_detection.one_class_svm import OneClassSVMDE
from anomaly_detection.types import TrafficType, DecisionEngine
import pandas as pd
import os.path
from anomaly_detection.db import DBConnector
import uuid
import pickle


class AnomalyDetector:
    def __init__(self, db: DBConnector, classification_id: str, decision_engine: DecisionEngine):
        self.preprocessor = Preprocessor()
        self.decision_engine: DecisionEngine = decision_engine
        self.db: DBConnector = db
        self.classification_id = classification_id
        self.init_db()

    def init_db(self):
        if self.db.exists_classification(self.classification_id):
            raise ValueError(
                "classification with id '%s' already exists in the database!" % self.classification_id)
        pickle_dump = self.decision_engine.serialize()
        model_id = str(uuid.uuid4())
        self.db.save_model_info(
            model_id=model_id, decision_engine=self.decision_engine.get_name(), pickle_dump=pickle_dump)
        self.db.save_classification_info(
            classification_id=self.classification_id, model_id=model_id)

    def build_profile(self, traffic_data):
        self.preprocessor.initialize(traffic_data)
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        self.decision_engine.fit(preprocessed)

    def feed_traffic(self, ids, traffic_data, traffic_type=TrafficType.UNKNOWN):
        if len(ids) != len(traffic_data):
            raise ValueError(
                f"Length of ids and traffic data must be equal! len(ids)={len(ids)}, len(traffic_data)={len(traffic_data)}")
        preprocessed = self.preprocessor.preprocess_data(traffic_data)
        predictions = self.decision_engine.classify(preprocessed)
        self.db.save_classifications(self.classification_id, ids, predictions)


class Preprocessor:
    def __init__(self):
        self.normalizer = Pipeline(
            [("minmax", MinMaxScaler()), ("standard", StandardScaler())])

    def initialize(self, traffic_data):
        self.normalizer.fit(traffic_data)

    def preprocess_data(self, traffic_data):
        return self.normalizer.transform(traffic_data)
