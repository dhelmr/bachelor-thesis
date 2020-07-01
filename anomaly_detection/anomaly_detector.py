import logging
import pickle
import typing as t

import numpy as np

from anomaly_detection.types import TrafficType, DecisionEngine, Transformer, FeatureExtractor, ClassificationResults, \
    PacketReader


class AnomalyDetectorModel:
    def __init__(self, decision_engine: DecisionEngine, feature_extractor: FeatureExtractor,
                 transformers: t.Sequence[Transformer]):
        self.transformers: t.Sequence[Transformer] = transformers
        self.decision_engine: DecisionEngine = decision_engine
        self.feature_extractor: FeatureExtractor = feature_extractor

    def build_profile(self, packet_reader: PacketReader):
        logging.info("Extract features...")
        features = self.feature_extractor.fit_extract(packet_reader)
        logging.info("Apply feature transformations...")
        self._fit_transformers(features)
        preprocessed = self._apply_transformers(features)
        logging.info("Start decision engine training ...")
        self.decision_engine.fit(preprocessed, traffic_type=TrafficType.BENIGN)

    def feed_traffic(self, classification_id: str, ids: t.Sequence[str], packet_reader: PacketReader):
        features = self.feature_extractor.extract_features(packet_reader)
        preprocessed = self._apply_transformers(features)
        de_result = self.decision_engine.classify(preprocessed)
        predictions = self.feature_extractor.map_backwards(packet_reader, de_result)
        return ClassificationResults(classification_id, ids, predictions)

    def _fit_transformers(self, traffic_data: np.ndarray):
        transformed = traffic_data
        for t in self.transformers:
            t.fit(transformed)
            transformed = t.transform(transformed)
            logging.info("Applied %s", t.get_name())

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


