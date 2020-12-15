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
        report = {}
        for training_set in records["traffic_name"].unique():
            training_set_records = records[records["traffic_name"] == training_set]
            part_names = training_set_records["part_name"].unique()
            report.update(
                {
                    f"{training_set}_{part_name}": self._sort_group(
                        training_set_records[
                            training_set_records["part_name"] == part_name
                        ]
                    )
                    for part_name in part_names
                }
            )
        print(report)
        if output_format is ReportOutputFormat.JSON:
            with open(output_path, "w") as f:
                json.dump(report, f)
        elif output_format is ReportOutputFormat.CSV:
            for part_name, metrics in report.items():
                part_name_esc = part_name.replace("/", "_")
                for metric_name, best_evaluations in metrics.items():
                    df = pandas.DataFrame(best_evaluations)
                    path = os.path.join(
                        output_path,
                        f"{model_part_name}_{part_name_esc}_{metric_name}.csv",
                    )
                    df.to_csv(path)

    def _sort_group(self, records):
        sorted_by_metrics = [
            (
                metric_name,
                records[(records[metric_name] >= 0) | (records[metric_name] <= 1)]
                .sort_values(by=[metric_name], ascending=False)
                .head(self.best_n),
            )
            for metric_name in self.sort_by_metrics
        ]
        as_dict_filtered = {
            metric: records.to_dict(orient="records")
            for metric, records in sorted_by_metrics
        }

        return as_dict_filtered
