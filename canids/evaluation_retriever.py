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

    def unique_values(self, fixed_param: str):
        param_index = self.fixed_hyperparams.index(fixed_param)
        param_values = {t[param_index] for t in self.groups.keys()}
        return param_values


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
        self.ignore_hyperparams = ["model_id"]
        self._db_entries = None
        self.retrieve() if retrieve_immediately else None

    def _get_db_entries(self, model_part_name: str):
        evaluations, hyperparams = self.db.get_evaluations_by_model_param(
            model_part_name
        )
        return DbEntries(evaluations, hyperparams)

    def retrieve(self):
        self._db_entries = self._get_db_entries(self.model_part_name)
        if len(self._db_entries.evaluations) == 0:
            raise ValueError("No evaluations found in database.")

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
            if hyperparam not in self.ignore_hyperparams
        }
        return groups

    def group_for_hyperparam(self, variable_param: str):
        self._check_state()
        if variable_param not in self._db_entries.hyperparams:
            raise ValueError(
                "%s is not in hyperparameters of %s"
                % (variable_param, self.model_part_name)
            )
        evaluations = self._db_entries.evaluations.copy(deep=True)
        fixed_params = [
            param
            for param in self._db_entries.hyperparams
            if param != variable_param and param not in self.ignore_hyperparams
        ] + self.additional_fixed_params
        if len(evaluations) == 0:
            return HyperparamGrouping(
                variable_hyperparam=variable_param,
                fixed_hyperparams=fixed_params,
                groups=[],
            )
        evaluations["fixed_param_values"] = evaluations.apply(
            lambda row: tuple([row[param] for param in fixed_params]), axis=1
        )
        grouped = evaluations.groupby(evaluations["fixed_param_values"]).apply(
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
