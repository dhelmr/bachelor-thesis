import argparse
import logging
import pickle

from sklearn.neighbors import LocalOutlierFactor

from anomaly_detection.types import TrafficType, DecisionEngine, Features

PREDICTION_ANOMALY_VALUE = -1
PREDICTION_NORMAL_VALUE = 1

LOF_METRICS = ['minkowski', 'cityblock', 'cosine', 'euclidean', 'l1', 'l2',
               'manhattan', 'braycurtis', 'canberra', 'chebyshev',
               'correlation', 'dice', 'hamming', 'jaccard', 'kulsinski',
               'mahalanobis', 'rogerstanimoto', 'russellrao',
               'seuclidean', 'sokalmichener', 'sokalsneath', 'sqeuclidean',
               'yule']
LOF_ALGORITHMS = ['auto', 'ball_tree', 'kd_tree', 'brute']


def create_parser(prog_name: str):
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--metric", choices=LOF_METRICS, help="Distance metric that is used for LOF",
                        default=LOF_METRICS[0])
    parser.add_argument("--minkowski-p", type=float, help="Parameter p when metric='minkowski'", default=2)
    parser.add_argument("--leaf-size", type=int, default=30, help="This canaffect the speed of the construction and "
                                                                  "query, as well as the memory        required to "
                                                                  "store the tree. The optimal value depends on the  "
                                                                  "       nature of the problem.")
    parser.add_argument("--algorithm", choices=LOF_ALGORITHMS, default=LOF_ALGORITHMS[0],
                        help="Algorithm used to compute the nearest neighbors with LOF")
    parser.add_argument("--n-neighbors", type=int, default=20, help="Number of neighbors to use by default for "
                                                                    "kneighbors queries. "
                                                                    "If n_neighbors is larger than the number of "
                                                                    "samples provided, "
                                                                    "all samples will be used.")
    return parser


class LocalOutlierFactorDE(DecisionEngine):
    def __init__(self, parsed_args):
        self.lof = LocalOutlierFactor(novelty=True, n_neighbors=parsed_args.n_neighbors,
                                      algorithm=parsed_args.algorithm,
                                      leaf_size=parsed_args.leaf_size,
                                      metric=parsed_args.metric, p=parsed_args.minkowski_p)
        logging.debug("Initialized LOF %s", self.lof)
        self._set_normal_traffic_type(TrafficType.BENIGN)

    def classify(self, features: Features):
        predictions = self.lof.predict(features.data)
        logging.info("Prediction done")
        traffic_type_labels = [
            self._prediction_to_traffic_type(p) for p in predictions]
        return traffic_type_labels

    def fit(self, features: Features, traffic_type: TrafficType):
        self.lof.fit(features.data)

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
