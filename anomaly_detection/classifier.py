import logging

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficReader

# If the classification id takes this value, it will be replaced by a new auto-generated id.
CLASSIFICATION_ID_AUTO_GENERATE = "auto"


class Classifier:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, model_id: str):
        self.traffic_reader: TrafficReader = traffic_reader
        self.model_id: str = model_id
        self.db: DBConnector = db
        self.ad: AnomalyDetectorModel = self._load_model(model_id)

    def start_classification(self, classification_id=CLASSIFICATION_ID_AUTO_GENERATE):
        if classification_id == CLASSIFICATION_ID_AUTO_GENERATE:
            classification_id = self._generate_new_id()
        self._init_db_for_classification(classification_id)
        for traffic in self.traffic_reader:
            name = traffic[0]
            logging.info("Detect anomalies in %s.", name)
            classification_results = self.ad.feed_traffic(
                classification_id,
                traffic=traffic)
            self.db.save_classifications(classification_results)

    def _init_db_for_classification(self, classification_id):
        db = self.db
        if db.exists_classification(classification_id):
            raise ValueError(
                "classification with id '%s' already exists in the database!" % classification_id)
        logging.info("Create new classification with id '%s'" % classification_id)
        db.save_classification_info(
            classification_id=classification_id, model_id=self.model_id)

    def _load_model(self, model_id: str):
        df = self.db.get_model_info(model_id)
        if len(df) == 0:
            raise ValueError(f"Model with id {model_id} cannot be found.")
        else:
            pickle_str = df["pickle_dump"][0]
            model = AnomalyDetectorModel.deserialize(pickle_str)
            return model

    def _generate_new_id(self):
        db = self.db
        known_ids = set(db.get_all_classifications(with_count=False).index.values.tolist())
        base_name = self.model_id
        i = 0
        while True:
            new_id = f"{base_name}-{i:01d}"
            i += 1
            if new_id not in known_ids:
                break
        return new_id
