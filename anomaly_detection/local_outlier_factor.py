from sklearn.neighbors import LocalOutlierFactor
from anomaly_detection.types import TrafficType,  DecisionEngine
import logging
import argparse
import pickle

PREDICTION_ANOMALY_VALUE = -1
PREDICTION_NORMAL_VALUE = 1

def create_parser(prog_name: str):
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    return parser

class LocalOutlierFactorDE(DecisionEngine):
    def __init__(self, args):
        self.lof = LocalOutlierFactor(novelty=True)
        logging.debug("Initialized LOF %s", self.lof)
        self._set_normal_traffic_type(TrafficType.BENIGN)

    def classify(self, traffic_data):
        predictions = self.lof.predict(traffic_data)
        logging.info("Prediction done")
        traffic_type_labels = [
            self._prediction_to_traffic_type(p) for p in predictions]
        return traffic_type_labels

    def fit(self, traffic_data, traffic_type=TrafficType.BENIGN):
        self.lof.fit(traffic_data)
            
    def _prediction_to_traffic_type(self, prediction_value: int):
        if prediction_value == PREDICTION_NORMAL_VALUE:
            return self.normal_traffic_type
        else:
            return self.anomaly_traffic_type
 
    def _set_normal_traffic_type(self, normal_traffic_type: TrafficType):
        self.normal_traffic_type = normal_traffic_type
        self.anomaly_traffic_type = normal_traffic_type.opposite_of()

    def get_name(self):
        return "local_outlier_factor"

    def serialize(self):
        return pickle.dumps(self)
