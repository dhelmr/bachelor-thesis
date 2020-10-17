import logging
import pickle
import typing as t

from anomaly_detection.types import TrafficType, DecisionEngine, Transformer, FeatureExtractor, ClassificationResults, \
    TrafficSequence, Features


class AnomalyDetectorModel:
    def __init__(self, decision_engine: DecisionEngine, feature_extractor: FeatureExtractor,
                 transformers: t.Sequence[Transformer]):
        self.transformers: t.Sequence[Transformer] = transformers
        self.decision_engine: DecisionEngine = decision_engine
        self.feature_extractor: FeatureExtractor = feature_extractor

    def fit_extract_features(self, traffic: TrafficSequence) -> Features:
        logging.debug("Extract features...")
        features = self.feature_extractor.fit_extract(traffic)
        features.validate()
        return features

    def build_profile(self, features: Features):
        logging.debug("Apply feature transformations...")
        transformed = self._fit_transform(features)
        logging.debug("Start decision engine training with features of shape %s ...", transformed.data.shape)
        self.decision_engine.fit(transformed, traffic_type=TrafficType.BENIGN)

    def feed_traffic(self, classification_id: str, traffic: TrafficSequence) -> ClassificationResults:
        logging.debug("Extract features...")
        features = self.feature_extractor.extract_features(traffic)
        features.validate()
        logging.debug("Feature have dimensions: ", features.data.ndim)
        transformed = self._apply_transformers(features)
        transformed.validate()
        logging.debug("Transformed features. Apply decision engine.")
        de_result = self.decision_engine.classify(transformed)
        logging.debug("Finished classifications. Start backwards mapping to packet ids.")
        predictions = self.feature_extractor.map_backwards(traffic, de_result)
        return ClassificationResults(classification_id, traffic.ids, predictions)

    def _fit_transform(self, features: Features):
        transformed = features
        for t in self.transformers:
            transformed = t.fit_transform(transformed)
            logging.info("Trained %s", t.get_name())
        return transformed

    def _apply_transformers(self, features: Features) -> Features:
        transformed = features
        for t in self.transformers:
            transformed = t.transform(transformed)
            transformed.validate()
            logging.info("Applied %s", t.get_name())
        return transformed

    def serialize(self):
        serialization_info = {
            "transformers": self.transformers,
            "decision_engine_class": self.decision_engine.__class__,
            "decision_engine_data": self.decision_engine.serialize(),
            "feature_extractor": self.feature_extractor
        }
        return pickle.dumps(serialization_info)

    @staticmethod
    def deserialize(s) -> "AnomalyDetectorModel":
        serialization_info = pickle.loads(s)
        de_class = serialization_info["decision_engine_class"]
        de_instance = de_class.deserialize(serialization_info["decision_engine_data"])
        return AnomalyDetectorModel(
            transformers=serialization_info["transformers"],
            feature_extractor=serialization_info["feature_extractor"],
            decision_engine=de_instance
        )
