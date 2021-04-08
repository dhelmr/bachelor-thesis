import json
import logging
from enum import Enum
from typing import List

from canids.db import DBConnector


class ReportOutputFormat(Enum):
    JSON = "json"
    CSV = "csv"


IMPORTANT_METRICS = [
    "f1_score",
    "mcc",
    "balanced_accuracy",
    "precision",
    "recall",
    "false_positives",
    "false_negatives",
    "support",
    "part_name",
    "traffic_name",
    "dataset_name",
    "train_dataset",
    "train_set_name",
    "classification_ms_per_packet",
]

RENAME_COLS = {
    "f1_score": "F1",
    "mcc": "MCC",
    "balanced_accuracy": "BA",
    "precision": "PR",
    "false_positives": "FP",
    "false_negatives": "FN",
    "true_positives": "TP",
    "true_negatives": "TN",
    "support": "N",
    "recall": "RC",
}


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
        self,
        model_part_names: List[str],
        output_path: str,
        output_format: ReportOutputFormat,
        filter_constants: bool,
        important_metrics: bool,
        query: str = None,
        rename_cols: bool = True,
        expand_transformers: bool = True,
    ):
        records, hyperparams = self.db.get_evaluations_by_model_part(*model_part_names)
        records.drop(columns=["model_id"], inplace=True)
        if expand_transformers:
            self._expand_transformers(records)
        records["transformers"] = records["transformers"].apply(lambda l: ", ".join(l))

        drop_cols = []
        for col in records.columns:
            if (
                filter_constants
                and col in hyperparams
                and len(records[col].unique()) <= 1
            ):
                drop_cols.append(col)
            if (
                important_metrics
                and col not in hyperparams
                and col not in IMPORTANT_METRICS
            ):
                drop_cols.append(col)
        logging.info("Drop %s", drop_cols)
        records.drop(columns=drop_cols, inplace=True)
        if rename_cols:
            records.rename(columns=RENAME_COLS, inplace=True)
            lower_hyperparams = {p: p.lower() for p in hyperparams}
            records.rename(columns=lower_hyperparams, inplace=True)
        if query is not None:
            logging.info("Execute query '%s'", query)
            records = records.query(query)
        if output_format is ReportOutputFormat.CSV:
            records.to_csv(output_path, index=False)
            return

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

    def _expand_transformers(self, records):
        # expand "transfomer" column and create own column for each transformer (1 if transformer is applied; 0 if not)
        all_transformers = set()
        records["transformers"] = records["transformers"].apply(
            lambda x: x.strip().split(",")
        )
        for _, row in records.iterrows():
            for transformer in row["transformers"]:
                all_transformers.add(transformer)
        for transformer_name in all_transformers:
            records[transformer_name] = records["transformers"].apply(
                lambda transformer_list: 1
                if transformer_name in transformer_list
                else 0
            )
