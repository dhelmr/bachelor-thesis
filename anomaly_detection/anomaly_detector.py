import logging
import pickle
import typing as t

import numpy as np

from anomaly_detection.types import TrafficType, DecisionEngine, Transformer, FeatureExtractor, ClassificationResults, \
    TrafficSequence


class AnomalyDetectorModel:
    def __init__(self, decision_engine: DecisionEngine, feature_extractor: FeatureExtractor,
                 transformers: t.Sequence[Transformer]):
        self.transformers: t.Sequence[Transformer] = transformers
        self.decision_engine: DecisionEngine = decision_engine
        self.feature_extractor: FeatureExtractor = feature_extractor

    def build_profile(self, traffic: TrafficSequence):
        logging.info("Extract features...")
        features = self.feature_extractor.fit_extract(traffic)
        logging.info("Apply feature transformations...")
        self._fit_transformers(features)
        transformed = self._apply_transformers(features)
        logging.info("Start decision engine training ...")
        self.decision_engine.fit(transformed, traffic_type=TrafficType.BENIGN)

    def feed_traffic(self, classification_id: str, traffic: TrafficSequence):
        features = self.feature_extractor.extract_features(traffic)
        transformed = self._apply_transformers(features)
        de_result = self.decision_engine.classify(transformed)
        predictions = self.feature_extractor.map_backwards(traffic, de_result)
        return ClassificationResults(classification_id, traffic.ids, predictions)

    def _fit_transformers(self, features: np.ndarray):
        transformed = features
        for t in self.transformers:
            t.fit(transformed)
            transformed = t.transform(transformed)
            logging.info("Trained %s", t.get_name())

    def _apply_transformers(self, features: np.ndarray):
        transformed = features
        for t in self.transformers:
            transformed = t.transform(transformed)
            logging.info("Applied %s", t.get_name())
        return transformed

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(s):
        obj = pickle.loads(s)
        if type(obj) is not AnomalyDetectorModel:
            raise ValueError("Invalid type of deserialized object (must be AnomalyDetector)! %s" % str(type(obj)))
        return obj


