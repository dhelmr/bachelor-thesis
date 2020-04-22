from sklearn.svm import OneClassSVM
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from anomaly_detection.traffic_type import TrafficType


# this is what the SVM yields if it classifies a traffic record as an anomaly
PREDICTION_ANOMALY_VALUE = -1
PREDICTION_NORMAL_VALUE = 1

class OneClassSVMDE:
    def __init__(self):
        self.svm = OneClassSVM(cache_size=500, coef0=0.0, kernel='rbf',
                          max_iter=-1, nu=0.001, shrinking=True, tol=0.001,
                          verbose=False)
        self._set_normal_traffic_type(TrafficType.BENIGN)

    def _set_normal_traffic_type(self, normal_traffic_type: TrafficType):
        self.normal_traffic_type = normal_traffic_type
        self.anomaly_traffic_type = normal_traffic_type.opposite_of()

    def fit(self, traffic_data, traffic_type=TrafficType.BENIGN):
        self._set_normal_traffic_type(traffic_type)
        return self.svm.fit(traffic_data)

    def _prediction_to_traffic_type(self, prediction_value: int):
        if prediction_value == PREDICTION_NORMAL_VALUE:
            return self.normal_traffic_type
        else:
            return self.anomaly_traffic_type

    def classify(self, traffic_data):
        predictions = self.svm.predict(traffic_data)
        traffic_type_labels = [self._prediction_to_traffic_type(p) for p in predictions]
        return traffic_type_labels
        