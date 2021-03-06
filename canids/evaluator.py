import json
import logging
import os.path
import typing as t

from sklearn.metrics import confusion_matrix

from canids.db import DBConnector
from canids.types import TrafficReader


class Evaluator:
    def __init__(
        self,
        db: DBConnector,
        traffic_reader: TrafficReader,
        report_file=None,
        force_overwrite: bool = False,
    ):
        self.traffic_reader: TrafficReader = traffic_reader
        self.db: DBConnector = db
        self.report_file = report_file
        if report_file is not None and os.path.exists(report_file):
            if not force_overwrite:
                raise FileExistsError(f"File already exists! {report_file}")
            else:
                logging.info(f"File {report_file} already exists, will overwrite.")

    def evaluate(
        self,
        classification_id: str,
        filter_traffic_names: t.Optional[t.List[str]] = None,
    ) -> dict:
        """
        Generate a evaluation report from a previous classification.

        This reads the records for a previous classification from the database, reads the actual values
        from the dataset and creates a confusion matrix. Various measurements, like f1-score, precision,
        recall and false detection rate (fdr) are generated. The report is then stored in the database.
        """
        pred = self.db.get_classifications_records(classification_id)
        if len(pred) == 0:
            raise ValueError(
                f"Classification with id '{classification_id}' does not exist!"
            )
        logging.info(
            f"Prediction log for classification with id {classification_id} loaded"
        )
        evaluation_dict = dict()
        for sequence in self.traffic_reader:
            for part_name, part_indexes in sequence.parts.items():
                name = sequence.name
                if (
                    filter_traffic_names is not None
                    and name not in filter_traffic_names
                ):
                    logging.debug("Ignore %s", name)
                    continue
                part_labels = sequence.labels.reindex(part_indexes)
                if part_name not in evaluation_dict:
                    evaluation_dict[part_name] = dict()
                evaluation_dict[part_name][name] = self.evaluate_traffic_sequence(
                    name, part_name, pred, true_labels=part_labels
                )
        for part_name, metrics in evaluation_dict.items():
            evaluation_dict[part_name]["total"] = self.calc_total_metrics(metrics)
        if self.report_file is not None:
            self.write_report(json.dumps(evaluation_dict, indent=4, sort_keys=True))
        self.store_in_db(
            evaluation_dict,
            classification_id,
            self.traffic_reader.get_testset_name(),
            self.traffic_reader.get_dataset_name(),
        )
        return evaluation_dict

    def evaluate_traffic_sequence(self, name, part_name, pred_labels, true_labels):
        logging.info(
            "Start evaluation of %s/%s (%i records)", name, part_name, len(true_labels)
        )
        # Convert traffic type to zero and ones
        labels = (
            true_labels.map(lambda x: x.value)
            .reindex(pred_labels.index.values)
            .dropna()
        )
        y_true = labels.values
        y_pred = pred_labels.reindex(labels.index.values).values
        # create confusion matrix and extract true/false positives/negatives from it
        cm = confusion_matrix(y_true, y_pred)
        if cm.shape == (1, 1):
            tn, fp, fn, tp = cm[0][0], 0, 0, 0
        else:
            tn, fp, fn, tp = cm.ravel()
        metrics = self.calc_measurements(int(tn), int(fp), int(fn), int(tp))
        logging.debug("Metrics for %s generated.", name)
        return metrics

    def calc_total_metrics(self, metrics_dict: dict):
        tn = self.get_summed_attr(metrics_dict, "true_negatives")
        fp = self.get_summed_attr(metrics_dict, "false_positives")
        fn = self.get_summed_attr(metrics_dict, "false_negatives")
        tp = self.get_summed_attr(metrics_dict, "true_positives")
        total_metrics = self.calc_measurements(tn, fp, fn, tp)
        return total_metrics

    @staticmethod
    def calc_measurements(tn: int, fp: int, fn: int, tp: int) -> dict:
        """
        Calculates different metrics for the values of a confusion matrix.
        For terminology see https://en.wikipedia.org/wiki/Precision_and_recall
        """
        sd = Evaluator.safe_divide
        metrics = dict()
        p = tp + fn
        n = tn + fp
        metrics["positives"] = p
        metrics["negatives"] = n
        metrics["recall"] = sd(tp, p)
        metrics["tnr"] = sd(tn, n)
        metrics["precision"] = sd(tp, (tp + fp))
        metrics["npv"] = sd(tn, (tn + fn))
        metrics["fpr"] = sd(fp, n)
        metrics["fdr"] = sd(fp, (fp + tp))
        metrics["for"] = sd(fn, (fn + tn))
        metrics["fnr"] = sd(fn, (fn + tp))
        metrics["accuracy"] = sd((tp + tn), (p + n))
        metrics["balanced_accuracy"] = (metrics["recall"] + metrics["tnr"]) / 2
        metrics["f1_score"] = sd(2 * tp, (2 * tp + fp + fn))
        metrics["true_negatives"] = tn
        metrics["true_positives"] = tp
        metrics["false_negatives"] = fn
        metrics["false_positives"] = fp
        metrics["kappa"] = 1 - sd(
            1 - metrics["accuracy"],
            1 - sd((tp + fp) * (tp + fn) + (fn + tn) * (fp + tn), pow(p + n, 2)),
        )
        metrics["mcc"] = sd(
            tp * tn - fp * fn, pow((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn), 0.5)
        )
        metrics["support"] = n + p
        return metrics

    @staticmethod
    def safe_divide(q1, q2) -> float:
        try:
            value = q1 / q2
        except ZeroDivisionError:
            value = float("Inf")
        return value

    @staticmethod
    def get_summed_attr(metrics_dict: dict, attribute: str):
        total = 0
        for section in metrics_dict:
            total += metrics_dict[section][attribute]
        return total

    def write_report(self, text: str):
        with open(self.report_file, "w") as f:
            f.write(text)
        logging.info("Report written into %s", self.report_file)

    def store_in_db(
        self, evaluation_dict, classification_id, testset_name: str, dataset_name: str
    ):
        for part_name, part_evaluations in evaluation_dict.items():
            for sequence_name, metrics in part_evaluations.items():
                if sequence_name == "total":
                    sequence_name = testset_name
                    is_aggregated = True
                else:
                    is_aggregated = False
                try:
                    self.db.store_evaluation(
                        classification_id,
                        sequence_name,
                        part_name,
                        is_aggregated,
                        dataset_name,
                        metrics,
                    )
                except Exception as e:
                    logging.error("Cannot store %s in db: %s", sequence_name, e)
