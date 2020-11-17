from typing import NamedTuple, List, Dict, Tuple, Any

import pandas

from canids.db import DBConnector


class DbEntries(NamedTuple):
    evaluations: pandas.DataFrame
    hyperparams: List[str]


class HyperparamGrouping(NamedTuple):
    fixed_hyperparams: List[str]
    groups: Dict[Tuple, List[Dict[str, Any]]]

    def as_tuples(self) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
        return [
            (
                {
                    self.fixed_hyperparams[i]: param
                    for i, param in enumerate(fixed_params)
                },
                evaluations,
            )
            for fixed_params, evaluations in self.groups.items()
        ]


class EvaluationRetriever:
    def __init__(self, db: DBConnector, model_part_name: str):
        self.db = db
        self.model_part_name = model_part_name
        self._db_entries = self._get_db_entries(model_part_name)

    def _get_db_entries(self, model_part_name: str):
        evaluations, hyperparams = self.db.get_evaluations_by_model_param(
            model_part_name
        )
        return DbEntries(evaluations, hyperparams)

    def group_for_hyperparam(self, param_name: str):
        if param_name not in self._db_entries.hyperparams:
            raise ValueError(
                "%s is not in hyperparameters of %s"
                % (param_name, self.model_part_name)
            )
        fixed_params = [
            param for param in self._db_entries.hyperparams if param != param_name
        ]
        self._db_entries.evaluations[
            "fixed_param_values"
        ] = self._db_entries.evaluations.apply(
            lambda row: tuple([row[param] for param in fixed_params]), axis=1
        )
        grouped = self._db_entries.evaluations.groupby(
            self._db_entries.evaluations["fixed_param_values"]
        ).apply(
            lambda rows: [
                row.drop(labels="fixed_param_values").to_dict()
                for _, row in rows.iterrows()
            ]
        )
        return HyperparamGrouping(
            groups=grouped.to_dict(), fixed_hyperparams=fixed_params
        )
