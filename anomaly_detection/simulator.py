from anomaly_detection.anomaly_detector import AnomalyDetector
import logging
from anomaly_detection.types import TrafficType

class Simulator:
    def __init__(self, anomaly_detector: AnomalyDetector, traffic_reader):
        self.ad = anomaly_detector
        self.traffic_reader = traffic_reader

    def start_train_test(self):
        _, normal_data, _ = self.traffic_reader.read_normal_data()
        logging.info(
            "Start training of normal profile (%i records)", len(normal_data))
        self.ad.build_profile(normal_data)
        logging.info("Training with normal profile done")
        for name, test_data, _ in self.traffic_reader:
            logging.info("Test file %s (%i records)", name, len(test_data))
            self.ad.feed_traffic(
                ids=test_data.index.values,
                traffic_data=test_data.values,
                traffic_type=TrafficType.UNKNOWN)
