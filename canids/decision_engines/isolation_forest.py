import argparse
import json
import logging
import pickle

from sklearn.ensemble import IsolationForest

from canids.types import TrafficType, DecisionEngine, Features

PREDICTION_ANOMALY_VALUE = -1
PREDICTION_NORMAL_VALUE = 1


class IsolationForestDE(DecisionEngine):
    def __init__(self, parsed_args):
        self.isolation_forest = IsolationForest(
            n_estimators=parsed_args.n_estimators,
            max_samples=parsed_args.max_samples,
            max_features=parsed_args.max_features,
            bootstrap=parsed_args.bootstrap,
        )
        logging.debug("Initialized Isolation forest %s", self.isolation_forest)
        self._set_normal_traffic_type(TrafficType.BENIGN)

    def classify(self, features: Features):
        predictions = self.isolation_forest.predict(features.data)
        logging.info("Prediction done")
        traffic_type_labels = [self._prediction_to_traffic_type(p) for p in predictions]
        return traffic_type_labels

    def fit(self, features: Features, traffic_type: TrafficType):
        self.isolation_forest.fit(features.data)

    def _prediction_to_traffic_type(self, prediction_value: int):
        if prediction_value == PREDICTION_NORMAL_VALUE:
            return self.normal_traffic_type
        else:
            return self.anomaly_traffic_type

    def _set_normal_traffic_type(self, normal_traffic_type: TrafficType):
        self.normal_traffic_type = normal_traffic_type
        self.anomaly_traffic_type = normal_traffic_type.opposite_of()

    @staticmethod
    def get_name():
        return "isolation_forest"

    def serialize(self):
        return pickle.dumps(self)

    def get_db_params_dict(self):
        return {
            "n_estimators": self.isolation_forest.n_estimators,
            "max_samples": self.isolation_forest.max_samples,
            "max_features": self.isolation_forest.max_features,
            "bootstrap": self.isolation_forest.bootstrap,
        }

    def get_id(self):
        params = json.dumps(self.get_db_params_dict(), sort_keys=True)
        return f"{self.get_name()}({params})"

    @staticmethod
    def create_parser(prog_name: str):
        parser = argparse.ArgumentParser(
            prog=prog_name, formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument(
            "--n-estimators",
            default=100,
            help="The number of base estimators in the ensemble.",
            type=int,
        )
        parser.add_argument(
            "--max-samples",
            type=float,
            help="The ratio of samples to draw from X to train each base estimator",
            default=0.01,
        )
        parser.add_argument(
            "--max-features",
            type=float,
            help="The ratio of features to draw from X to train each base estimator",
            default=0.5,
        )
        parser.add_argument(
            "--bootstrap",
            type=bool,
            default=False,
            help="If True, individual trees are fit on random subsets of the training data sampled with replacement. If False, sampling without replacement is performed.",
        )
        return parser
