import logging
import uuid

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficReader


class ModelTrainer:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader,
                 anomaly_detector: AnomalyDetectorModel, model_id: str = str(uuid.uuid4())):
        self.traffic_reader: TrafficReader = traffic_reader
        self.model_id: str = model_id
        self.db: DBConnector = db
        self.ad: AnomalyDetectorModel = anomaly_detector

    def start_training(self):
        if self.db.exists_model(self.model_id):
            raise ValueError("Model with id '%s' already exists!" % self.model_id)
        _, normal_data, _ = self.traffic_reader.read_normal_data()
        logging.info(
            "Start training of normal profile (%i records)", len(normal_data))
        self.ad.build_profile(normal_data.values)
        logging.info("Training with normal profile done")
        self._save_model()

    def _save_model(self):
        pickle_dump = self.ad.serialize()
        preprocessor_names = [p.get_name() for p in self.ad.preprocessors]
        self.db.save_model_info(
            model_id=self.model_id, decision_engine=self.ad.decision_engine.get_name(),
            preprocessors=preprocessor_names, pickle_dump=pickle_dump)
        logging.debug("Store model with id '%s' in database" % self.model_id)
