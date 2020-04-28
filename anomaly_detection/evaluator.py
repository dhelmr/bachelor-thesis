from anomaly_detection.anomaly_detector import PredictionLog
from anomaly_detection.traffic_type import TrafficType
from sklearn.metrics import classification_report, confusion_matrix
import logging
import os.path
import json


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
        evaluation_dict = dict()
        for name, _, traffic_type in self.traffic_reader:
            logging.info("Start evaluation of %s (%i records)",
                         name, len(traffic_type))
            labels = traffic_type.map(lambda x: x.value)
            y_true = labels.values
            y_pred = log.loc[labels.index.values].values
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            metrics = self.calc_measurements(int(tn),int(fp),int(fn),int(tp))
            evaluation_dict[name] = metrics
            logging.debug("Metrics for %s generated.", name)
        evaluation_dict["total"] = self.calc_total_metrics(evaluation_dict)
        self.write_report(json.dumps(
            evaluation_dict, indent=4, sort_keys=True))
        logging.info("Report written into %s", self.report_file)

    def calc_total_metrics(self, metrics_dict):
        tn = self.get_summed_attr(metrics_dict, "true_negatives")
        fp = self.get_summed_attr(metrics_dict, "false_positives")
        fn = self.get_summed_attr(metrics_dict, "false_negatives")
        tp = self.get_summed_attr(metrics_dict, "true_positives")
        total_metrics = self.calc_measurements(tn, fp, fn, tp)
        return total_metrics

    def calc_weighted_average(self, metrics_dict, metric_name, total_support=None):
        # TODO this causes n² complexity (but should not matter)
        total_support = self.get_summed_attr(metrics_dict, "support")
        weighted_avg = 0
        for section in metrics_dict:
            metrics = metrics_dict[section]
            support = metrics["support"]
            fraction = support/total_support
            weighted_avg += fraction * metrics[metric_name]
        return weighted_avg

    def calc_measurements(self, tn, fp, fn, tp):
        """
        Calculates different metrics for the values of a confusion matrix.
        For terminology see https://en.wikipedia.org/wiki/Precision_and_recall
        """
        metrics = dict()
        p = tp+fn
        n = tn + fp
        metrics["positives"] = p
        metrics["negatives"] = n
        metrics["recall"] = tp/p
        metrics["tnr"] = tn/n
        metrics["precision"] = tp/(tp+fp)
        metrics["npv"] = tn/(tn+fn)
        metrics["fpr"] = fp/n
        metrics["fdr"] = fp/(fp+tp)
        metrics["for"] = fn/(fn+tn)
        metrics["accuracy"] = (tp+tn)/(p+n)
        metrics["balanced_accuracy"] = (metrics["recall"] + metrics["tnr"])/2
        metrics["f1_score"] = 2*tp/(2*tp+fp+fn)
        metrics["true_negatives"] = tn
        metrics["true_positives"] = tp
        metrics["false_negatives"] = fn
        metrics["false_positives"] = fp
        metrics["support"] = n+p
        return metrics

    def get_summed_attr(self, metrics_dict, attribute):
        total = 0
        for section in metrics_dict:
            total += metrics_dict[section][attribute]
        return total

    def is_numeric(self, obj):
        return type(obj) in (float, int)

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
