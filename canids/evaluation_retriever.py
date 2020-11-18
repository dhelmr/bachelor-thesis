from typing import NamedTuple, List, Dict, Tuple, Any

import pandas

from canids.db import DBConnector


class DbEntries(NamedTuple):
    evaluations: pandas.DataFrame
    hyperparams: List[str]


class HyperparamGrouping(NamedTuple):
    variable_hyperparam: str
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
    def __init__(
        self,
        db: DBConnector,
        model_part_name: str,
        retrieve_immediately=True,
    ):
        self.db = db
        self.model_part_name = model_part_name
        self.additional_fixed_params = ["dataset_name", "traffic_name", "part_name"]
        self._db_entries = (
            self._get_db_entries(model_part_name) if retrieve_immediately else None
        )

    def _get_db_entries(self, model_part_name: str):
        evaluations, hyperparams = self.db.get_evaluations_by_model_param(
            model_part_name
        )
        return DbEntries(evaluations, hyperparams)

    def retrieve(self):
        self._db_entries = self._get_db_entries(self.model_part_name)

    def _check_state(self):
        if self._db_entries is None:
            raise RuntimeError(
                "Database entries are not retrieved yet! First call retrieve(), or use retrieve_immediately=True."
            )

    def group_for_all(self):
        self._check_state()
        groups = {
            hyperparam: self.group_for_hyperparam(hyperparam)
            for hyperparam in self._db_entries.hyperparams
        }
        return groups

    def group_for_hyperparam(self, variable_param: str):
        self._check_state()
        if variable_param not in self._db_entries.hyperparams:
            raise ValueError(
                "%s is not in hyperparameters of %s"
                % (variable_param, self.model_part_name)
            )
        fixed_params = [
            param for param in self._db_entries.hyperparams if param != variable_param
        ] + self.additional_fixed_params
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
            variable_hyperparam=variable_param,
            groups=grouped.to_dict(),
            fixed_hyperparams=fixed_params,
        )
