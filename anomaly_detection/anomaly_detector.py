import logging
import pickle
import typing as t

import numpy as np

from anomaly_detection.types import TrafficType, DecisionEngine, Preprocessor, FeatureExtractor, ClassificationResults


class AnomalyDetectorModel:
    def __init__(self, decision_engine: DecisionEngine, feature_extractor: FeatureExtractor,
                 preprocessors: t.Sequence[Preprocessor]):
        self.preprocessors: t.Sequence[Preprocessor] = preprocessors
        self.decision_engine: DecisionEngine = decision_engine
        self.feature_extractor: FeatureExtractor = feature_extractor

    def build_profile(self, pcap_file: str):
        logging.info("Extract features...")
        features = self.feature_extractor.fit_extract(pcap_file)
        logging.info("Apply feature transformations...")
        self._fit_preprocessors(features)
        preprocessed = self._transform_with_preprocessors(features)
        logging.info("Start model training ...")
        self.decision_engine.fit(preprocessed, traffic_type=TrafficType.BENIGN)

    def feed_traffic(self, classification_id: str, ids: t.Sequence[str], pcap_file: str):
        features = self.feature_extractor.extract_features(pcap_file)
        preprocessed = self._transform_with_preprocessors(features)
        de_result = self.decision_engine.classify(preprocessed)
        predictions = self.feature_extractor.map_backwards(pcap_file, de_result)
        return ClassificationResults(classification_id, ids, predictions)

    def _fit_preprocessors(self, traffic_data: np.ndarray):
        transformed = traffic_data
        for p in self.preprocessors:
            p.fit(transformed)
            transformed = p.transform(transformed)

    def _transform_with_preprocessors(self, features: np.ndarray):
        transformed = features
        for p in self.preprocessors:
            transformed = p.transform(transformed)
        return transformed

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(s):
        obj = pickle.loads(s)
        if type(obj) is not AnomalyDetectorModel:
            raise ValueError("Invalid type of deserialized object (must be AnomalyDetector)! %s" % str(type(obj)))
        return obj


