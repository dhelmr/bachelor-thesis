from anomaly_detection.anomaly_detector import AnomalyDetector
import logging
from anomaly_detection.types import TrafficType
import uuid

# If the classification id takes this value, it will be replaced by a new auto-generated id.
CLASSIFICATION_ID_AUTO_GENERATE="auto"

class Simulator:
    def __init__(self, anomaly_detector: AnomalyDetector, traffic_reader, classification_id=CLASSIFICATION_ID_AUTO_GENERATE):
        self.ad = anomaly_detector
        self.traffic_reader = traffic_reader    
        if classification_id is CLASSIFICATION_ID_AUTO_GENERATE:
            classification_id = self._generate_new_id()
        self.classification_id = classification_id
        self._init_db()

    def _generate_new_id(self):
        db = self.ad.db
        known_ids = set(db.get_classification_info(with_count=False).index.values.tolist())
        base_name = self.ad.decision_engine.get_name()
        new_id = ""
        i = 0
        while True:
            new_id = f"{base_name}-{i:05d}"
            i+=1
            if new_id not in known_ids:
                break
        return new_id

    def _init_db(self):
        db = self.ad.db
        if db.exists_classification(self.classification_id):
            raise ValueError(
                "classification with id '%s' already exists in the database!" % self.classification_id)
        logging.info("Create new classification with id '%s'" % self.classification_id)
        pickle_dump = self.ad.decision_engine.serialize()
        model_id = str(uuid.uuid4())
        db.save_model_info(
            model_id=model_id, decision_engine=self.ad.decision_engine.get_name(), pickle_dump=pickle_dump)
        db.save_classification_info(
            classification_id=self.classification_id, model_id=model_id)

    def start_train_test(self):
        _, normal_data, _ = self.traffic_reader.read_normal_data()
        logging.info(
            "Start training of normal profile (%i records)", len(normal_data))
        self.ad.build_profile(normal_data)
        logging.info("Training with normal profile done")
        for name, test_data, _ in self.traffic_reader:
            logging.info("Test file %s (%i records)", name, len(test_data))
            self.ad.feed_traffic(
                classification_id=self.classification_id,
                ids=test_data.index.values,
                traffic_data=test_data.values,
                traffic_type=TrafficType.UNKNOWN)
        
    
