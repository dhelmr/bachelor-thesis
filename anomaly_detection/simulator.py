import logging
import uuid

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficType, TrafficReader

# If the classification id takes this value, it will be replaced by a new auto-generated id.
CLASSIFICATION_ID_AUTO_GENERATE = "auto"


class Simulator:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, model_id: str = str(uuid.uuid4()),
                 anomaly_detector: AnomalyDetectorModel = None):
        self.traffic_reader: TrafficReader = traffic_reader
        self.model_id: str = model_id
        self.db: DBConnector = db
        self.ad: AnomalyDetectorModel = self._load_model_or_default(anomaly_detector)
        if self.ad is None:
            raise ValueError("There is no model with id '%s'!" % model_id)

    def _init_db_for_classification(self, classification_id):
        db = self.db
        if db.exists_classification(classification_id):
            raise ValueError(
                "classification with id '%s' already exists in the database!" % classification_id)
        logging.info("Create new classification with id '%s'" % classification_id)
        db.save_classification_info(
            classification_id=classification_id, model_id=self.model_id)

    def _save_model(self):
        pickle_dump = self.ad.serialize()
        preprocessor_names = [p.get_name() for p in self.ad.preprocessors]
        self.db.save_model_info(
            model_id=self.model_id, decision_engine=self.ad.decision_engine.get_name(),
            preprocessors=preprocessor_names, pickle_dump=pickle_dump)
        logging.debug("Store model with id '%s' in database" % self.model_id)

    def _load_model_or_default(self, default_model: AnomalyDetectorModel):
        df = self.db.get_model_info(self.model_id)
        if len(df) == 0:
            return default_model
        else:
            pickle_str = df["pickle_dump"][0]
            model = AnomalyDetectorModel.deserialize(pickle_str)
            return model

    def start_training(self):
        if self.db.exists_model(self.model_id):
            raise ValueError("Model with id '%s' already exists!" % self.model_id)
        _, normal_data, _ = self.traffic_reader.read_normal_data()
        logging.info(
            "Start training of normal profile (%i records)", len(normal_data))
        self.ad.build_profile(normal_data.values)
        logging.info("Training with normal profile done")
        self._save_model()

    def start_classification(self, classification_id=CLASSIFICATION_ID_AUTO_GENERATE):
        if classification_id == CLASSIFICATION_ID_AUTO_GENERATE:
            classification_id = self._generate_new_id()
        self._init_db_for_classification(classification_id)
        for name, test_data, _ in self.traffic_reader:
            logging.info("Detect anomalies in %s (%i records)", name, len(test_data))
            self.ad.feed_traffic(
                self.db,
                classification_id,
                ids=test_data.index.values,
                traffic_data=test_data.values,
                traffic_type=TrafficType.UNKNOWN)

    def _generate_new_id(self):
        db = self.db
        known_ids = set(db.get_all_classifications(with_count=False).index.values.tolist())
        base_name = self.ad.decision_engine.get_name()
        i = 0
        while True:
            new_id = f"{base_name}-{i:05d}"
            i += 1
            if new_id not in known_ids:
                break
        return new_id
