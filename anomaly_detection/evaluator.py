import json
import logging
import os.path

from sklearn.metrics import confusion_matrix

from anomaly_detection.db import DBConnector
from anomaly_detection.types import TrafficReader


class Evaluator:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, report_file: str):
        self.traffic_reader = traffic_reader
        self.db: DBConnector = db
        self.report_file = report_file
        if os.path.exists(report_file):
            raise FileExistsError(f"File already exists! {report_file}")

    def evaluate(self, classification_id: str):
        """
        Generate a evaluation report from a previous classification. 

        This reads the records for a previous classification from the database, reads the actual values 
        from the dataset and creates a confusion matrix. Various measurements, like f1-score, precision,
        recall and false detection rate (fdr) are generated. The report is then saved as json.
        """
        pred = self.db.get_classifications_records(classification_id)
        if len(pred) == 0:
            raise ValueError(f"Classification with id '{classification_id}' does not exist!")
        logging.info(f"Prediction log for classification with id {classification_id} loaded")
        evaluation_dict = dict()
        for name, _, _, traffic_types in self.traffic_reader:
            logging.info("Start evaluation of %s (%i records)",
                         name, len(traffic_types))
            # Convert traffic type to zero and ones
            labels = traffic_types.map(lambda x: x.value)
            y_true = labels.values
            y_pred = pred.loc[labels.index.values].values
            # TODO case when only one label is set everywhere (no matrix is generated)
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            metrics = self.calc_measurements(
                int(tn), int(fp), int(fn), int(tp))
            evaluation_dict[name] = metrics
            logging.debug("Metrics for %s generated.", name)
        evaluation_dict["total"] = self.calc_total_metrics(evaluation_dict)
        self.write_report(json.dumps(
            evaluation_dict, indent=4, sort_keys=True))
        logging.info("Report written into %s", self.report_file)

    def calc_total_metrics(self, metrics_dict: dict):
        tn = self.get_summed_attr(metrics_dict, "true_negatives")
        fp = self.get_summed_attr(metrics_dict, "false_positives")
        fn = self.get_summed_attr(metrics_dict, "false_negatives")
        tp = self.get_summed_attr(metrics_dict, "true_positives")
        total_metrics = self.calc_measurements(tn, fp, fn, tp)
        return total_metrics

    def calc_weighted_average(self, metrics_dict: dict, metric_name: str, total_support=None):
        # TODO this causes n² complexity (but should not matter)
        total_support = self.get_summed_attr(metrics_dict, "support")
        weighted_avg = 0
        for section in metrics_dict:
            metrics = metrics_dict[section]
            support = metrics["support"]
            fraction = support / total_support
            weighted_avg += fraction * metrics[metric_name]
        return weighted_avg

    def calc_measurements(self, tn: int, fp: int, fn: int, tp: int):
        """
        Calculates different metrics for the values of a confusion matrix.
        For terminology see https://en.wikipedia.org/wiki/Precision_and_recall
        """
        metrics = dict()
        p = tp + fn
        n = tn + fp
        metrics["positives"] = p
        metrics["negatives"] = n
        metrics["recall"] = self.safe_divide(tp, p)
        metrics["tnr"] = self.safe_divide(tn, n)
        metrics["precision"] = self.safe_divide(tp, (tp + fp))
        metrics["npv"] = self.safe_divide(tn, (tn + fn))
        metrics["fpr"] = self.safe_divide(fp, n)
        metrics["fdr"] = self.safe_divide(fp, (fp + tp))
        metrics["for"] = self.safe_divide(fn, (fn + tn))
        metrics["accuracy"] = self.safe_divide((tp + tn), (p + n))
        metrics["balanced_accuracy"] = (metrics["recall"] + metrics["tnr"]) / 2
        metrics["f1_score"] = self.safe_divide(2 * tp, (2 * tp + fp + fn))
        metrics["true_negatives"] = tn
        metrics["true_positives"] = tp
        metrics["false_negatives"] = fn
        metrics["false_positives"] = fp
        metrics["support"] = n + p
        return metrics

    def safe_divide(self, q1, q2) -> float:
        try:
            value = q1 / q2
        except ZeroDivisionError:
            value = float('Inf')
        return value

    def get_summed_attr(self, metrics_dict: dict, attribute: str):
        total = 0
        for section in metrics_dict:
            total += metrics_dict[section][attribute]
        return total

    def write_report(self, text: str):
        file = open(self.report_file, "a")
        if not text.endswith("\n"):
            text += "\n"
        file.write(text)
        file.close()
