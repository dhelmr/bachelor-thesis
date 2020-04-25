from anomaly_detection.anomaly_detector import PredictionLog
from anomaly_detection.traffic_type import TrafficType
from sklearn.metrics import classification_report
import logging
import os.path


class Evaluator:
    def __init__(self, prediction_log: PredictionLog, traffic_reader, report_file):
        self.traffic_reader = traffic_reader
        self.prediction_log = prediction_log
        self.report_file = report_file
        if os.path.exists(report_file):
            raise FileExistsError(f"File already exists! {report_file}")

    def evaluate(self):
        log = self.prediction_log.read()
        logging.info("Prediction log loaded")
        for name, _, traffic_type in self.traffic_reader:
            self.write_report(f">>> {name}")
            logging.info("Start evaluation of %s (%i records)",
                         name, len(traffic_type))
            labels = traffic_type.map(lambda x: x.value)
            y_true = labels.values
            y_pred = log.loc[labels.index.values].values
            target_names = ["BENIGN", "ATTACK"]  # TODO generic
            self.write_report(classification_report(
                y_true, y_pred, target_names=target_names))
            logging.debug("Report for %s written.", name)
        logging.info("Report written into %s", self.report_file)

    def write_report(self, text):
        file = open(self.report_file, "a")
        if not text.endswith("\n"):
            text += "\n"
        file.write(text)
        file.close()


class Simulator:
    def __init__(self, anomaly_detector, traffic_reader):
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
