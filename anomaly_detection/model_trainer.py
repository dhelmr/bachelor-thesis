import logging

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficReader

MODEL_ID_AUTO_GENERATE = "auto"


class ModelTrainer:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader,
                 anomaly_detector: AnomalyDetectorModel, model_id: str = MODEL_ID_AUTO_GENERATE):
        self.traffic_reader: TrafficReader = traffic_reader
        self.db: DBConnector = db
        self.ad: AnomalyDetectorModel = anomaly_detector
        self.model_id: str = model_id

    def start_training(self, store_features=False, load_features=False):
        if self.db.exists_model(self.model_id):
            raise ValueError("Model with id '%s' already exists!" % self.model_id)
        traffic = self.traffic_reader.read_normal_data()
        name = traffic[0]
        logging.info(
            "Start training of normal profile (%s)", name)
        fe_id = self.ad.feature_extractor.get_id()
        features_loaded = False
        if load_features and traffic.is_consistent and self.db.exist_features(fe_id, traffic.name):
            try:
                logging.info("Load features from database...")
                features = self.db.load_features(fe_id, traffic.name)
                previous_model = self.db.load_model_by_fe_id(fe_id, traffic.name)
                self.ad.feature_extractor = previous_model.feature_extractor
                features_loaded = True
            except Exception as e:
                logging.error("Features could not be loaded...", e)
        elif load_features:
            logging.info("Cannot load features from db... Start feature extraction...")
        if not features_loaded:
            features = self.ad.fit_extract_features(traffic)
        self.ad.build_profile(features)

        logging.info("Training with normal profile done.")
        self._save_model()
        if store_features and not features_loaded:
            logging.info("Store extracted features in database...")
            try:
                self.db.store_features(fe_id, traffic.name, features, self.model_id)
            except Exception as e:
                logging.error("Cannot store features in database: ", e)

    def _save_model(self):
        pickle_dump = self.ad.serialize()
        transformer_names = [p.get_name() for p in self.ad.transformers]
        if self.model_id == MODEL_ID_AUTO_GENERATE:
            self.model_id = self._auto_generate_id()
            logging.info("Use model id %s" % self.model_id)
        self.db.save_model_info(
            model_id=self.model_id, decision_engine=self.ad.decision_engine.get_name(),
            transformers=transformer_names, feature_extractor=self.ad.feature_extractor.get_name(),
            pickle_dump=pickle_dump)
        logging.debug("Store model with id '%s' in database" % self.model_id)

    def _auto_generate_id(self) -> str:
        base_name = "%s-%s" % (self.ad.feature_extractor.get_name(), self.ad.decision_engine.get_name())
        i = 0
        while True:
            new_id = f"{base_name}-{i:01d}"
            i += 1
            if not self.db.exists_model(new_id):
                return new_id
