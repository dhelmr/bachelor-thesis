import json
import os
from enum import Enum

import pandas

from canids.db import DBConnector


class ReportOutputFormat(Enum):
    JSON = "json"
    CSV = "csv"


class ReportGenerator:
    def __init__(self, db: DBConnector):
        self.db = db
        self.sort_by_metrics = {
            "f1_score",
            "mcc",
            "precision",
            "kappa",
            "balanced_accuracy",
        }
        self.best_n = 30

    def make_report(
        self, model_part_name: str, output_path: str, output_format: ReportOutputFormat
    ):
        records, hyperparams = self.db.get_evaluations_by_model_part(model_part_name)
        part_names = records["part_name"].unique()
        report = {
            part_name: self._sort_group(records[records["part_name"] == part_name])
            for part_name in part_names
        }
        if output_format is ReportOutputFormat.JSON:
            with open(output_path, "w") as f:
                json.dump(report, f)
        elif output_format is ReportOutputFormat.CSV:
            for part_name, metrics in report.items():
                for metric_name, best_evaluations in metrics.items():
                    df = pandas.DataFrame(best_evaluations)
                    path = os.path.join(
                        output_path, f"{model_part_name}_{part_name}_{metric_name}.csv"
                    )
                    df.to_csv(path)

    def _sort_group(self, records):
        sorted_by_metrics = [
            (
                metric_name,
                records.sort_values(by=[metric_name], ascending=False).head(
                    self.best_n
                ),
            )
            for metric_name in self.sort_by_metrics
        ]
        as_dict_filtered = {
            metric: records.to_dict(orient="records")
            for metric, records in sorted_by_metrics
        }

        return as_dict_filtered
