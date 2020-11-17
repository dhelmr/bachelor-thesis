import logging
import time
import uuid

from canids.anomaly_detector import AnomalyDetectorModel
from canids.db import DBConnector
from canids.types import TrafficReader

# If the classification id takes this value, it will be replaced by a new auto-generated id.
CLASSIFICATION_ID_AUTO_GENERATE = "auto"


class Classifier:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, model_id: str):
        self.traffic_reader: TrafficReader = traffic_reader
        self.model_id: str = model_id
        self.db: DBConnector = db
        self.ad: AnomalyDetectorModel = self.db.load_model(model_id)

    def start_classification(self, classification_id=CLASSIFICATION_ID_AUTO_GENERATE):
        if classification_id == CLASSIFICATION_ID_AUTO_GENERATE:
            classification_id = self._generate_new_id()
        self._init_db_for_classification(classification_id)
        total_time = 0
        total_read_time = 0
        total_packet_count = 0
        for traffic in self.traffic_reader:
            packet_wrapper = CountTimeIterator(traffic.packet_reader)
            wrapped_traffic = traffic.copy_with(packet_reader=packet_wrapper)
            logging.info("Detect anomalies in %s.", traffic.name)
            start_time = time.time()
            classification_results = self.ad.feed_traffic(
                classification_id, traffic=wrapped_traffic
            )
            end_time = time.time()
            total_time += end_time - start_time
            total_read_time += packet_wrapper.get_total_time()
            total_packet_count += packet_wrapper.get_count()
            self.db.save_classifications(classification_results)
        self.db.finish_classification(
            classification_id,
            total_time=total_time,
            packet_count=total_packet_count,
            read_time=total_read_time,
        )
        return classification_id

    def _init_db_for_classification(self, classification_id):
        db = self.db
        if db.exists_classification(classification_id):
            raise ValueError(
                "classification with id '%s' already exists in the database!"
                % classification_id
            )
        logging.info("Create new classification with id '%s'" % classification_id)
        db.new_classification_info(
            classification_id=classification_id, model_id=self.model_id
        )

    def _generate_new_id(self):
        known_ids = set(
            self.db.get_all_classifications(with_count=False).index.values.tolist()
        )
        base_name = self.model_id
        while True:
            new_id = f"{base_name}/{uuid.uuid4().__str__()[:4]}"
            if new_id not in known_ids:
                return new_id


class CountTimeIterator:
    """Wrapper around an iterator that counts how many objects were yielded and
    how long it took to read the underlying iterator"""

    def __init__(self, original_reader):
        self._count = 0
        self._time_for_reading = 0
        self._original_reader = original_reader

    def __iter__(self):
        start_time = time.time()
        for item in self._original_reader:
            end_time = time.time()
            self._time_for_reading += end_time - start_time
            self._count += 1
            yield item
            start_time = time.time()

    def get_count(self):
        return self._count

    def get_total_time(self):
        return self._time_for_reading
