import argparse
import logging
import pickle

from sklearn.svm import OneClassSVM

from anomaly_detection.types import TrafficType, DecisionEngine, Features

# this is what the SVM yields if it classifies a traffic record as an anomaly
PREDICTION_ANOMALY_VALUE = -1
PREDICTION_NORMAL_VALUE = 1
AVAILABLE_KERNELS = ["rbf", "poly", "linear", "sigmoid"]


def create_parser(prog_name):
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--gamma", type=float, default=0.005,
                        help="Kernel coefficient for ‘rbf’, ‘poly’ and ‘sigmoid’ kernels")
    parser.add_argument("--nu", type=float, default=0.001,
                        help="An upper bound on the fraction of training errors and a lower bound of the fraction of support vectors. Should be in the interval (0, 1].")
    parser.add_argument(
        "--kernel", type=str, choices=AVAILABLE_KERNELS, default=AVAILABLE_KERNELS[0])
    parser.add_argument("--tolerance", type=float,
                        help="Tolerance for stopping criterion.", default=0.001)
    parser.add_argument(
        "--coef0", type=float,
        help="Independent term in kernel function. It is only significant in ‘poly’ and ‘sigmoid’", default=0.0)
    parser.add_argument("--max-iter", dest="max_iter", type=int,
                        help="Hard limit on iterations within solver, or -1 for no limit.", default=-1)
    parser.add_argument("--shrinking", type=bool,
                        help="Whether to use the shrinking heuristic.", default=True)
    parser.add_argument(
        "--degree", type=int, help="Degree of the polynomial kernel function (‘poly’). Ignored by all other kernels.",
        default=3)
    parser.add_argument("--cache-size", dest="cache_size", type=float,
                        help="Specify the size of the kernel cache (in MB).", default=500.0)
    return parser


class OneClassSVMDE(DecisionEngine):
    def __init__(self, parsed_args: argparse.Namespace):
        self.svm = OneClassSVM(cache_size=parsed_args.cache_size, coef0=parsed_args.coef0, kernel=parsed_args.kernel,
                               gamma=parsed_args.gamma,
                               max_iter=parsed_args.max_iter, nu=parsed_args.nu, shrinking=parsed_args.shrinking,
                               tol=parsed_args.tolerance,
                               verbose=True)
        logging.debug("Initialized OneClassSVM %s", self.svm)
        self._set_normal_traffic_type(TrafficType.BENIGN)

    def classify(self, features: Features):
        logging.info("Start prediction of traffic data")
        predictions = self.svm.predict(features.data)
        logging.info("Prediction done")
        traffic_type_labels = [
            self._prediction_to_traffic_type(p) for p in predictions]
        return traffic_type_labels

    def _set_normal_traffic_type(self, normal_traffic_type: TrafficType):
        self.normal_traffic_type = normal_traffic_type
        self.anomaly_traffic_type = normal_traffic_type.opposite_of()

    def fit(self, features: Features, traffic_type=TrafficType.BENIGN):
        self._set_normal_traffic_type(traffic_type)
        return self.svm.fit(features.data)

    def _prediction_to_traffic_type(self, prediction_value: int):
        if prediction_value == PREDICTION_NORMAL_VALUE:
            return self.normal_traffic_type
        else:
            return self.anomaly_traffic_type

    @staticmethod
    def get_name():
        return "one_class_svm"

    def serialize(self):
        return pickle.dumps(self)

    def __str__(self):
        return f"{self.svm})"

    def get_db_params_dict(self) -> dict:
        return {
            "cache_size": self.svm.cache_size,
            "coef0": self.svm.coef0,
            "kernel": self.svm.kernel,
            "gamma": self.svm.gamma,
            "max_iter": self.svm.max_iter,
            "nu": self.svm.nu,
            "shrinking": self.svm.shrinking,
            "tolerance": self.svm.tol
        }
