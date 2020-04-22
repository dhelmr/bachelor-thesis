from anomaly_detection.anomaly_detector import AnomalyDetector
from anomaly_detection.traffic_type import TrafficType
from sklearn.metrics import classification_report


class Evaluator:
    def __init__(self, anomaly_detector: AnomalyDetector, traffic_reader):
        self.traffic_reader = traffic_reader
        self.ad: AnomalyDetector = anomaly_detector

    def start_train_test(self):
        _, normal_data, _ = self.traffic_reader.read_normal_data()
        self.ad.build_profile(normal_data)
        print("Training done")
        for name, test_data, _ in self.traffic_reader:
            print(f"process {name}")
            self.ad.feed_traffic(
                ids=test_data.index.values,
                traffic_data=test_data.values,
                traffic_type=TrafficType.UNKNOWN)

    def evaluate(self):
        log = self.ad.prediction_log.read()
        for name, _, traffic_type in self.traffic_reader:
            print(f"process {name}")
            labels = traffic_type.map(lambda x: x.value)
            y_true = labels.values
            y_pred = log.loc[labels.index.values].values
            target_names = ["BENIGN", "ATTACK"] # TODO generic
            print(classification_report(y_true, y_pred, target_names=target_names))