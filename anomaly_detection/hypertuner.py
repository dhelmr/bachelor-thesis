import itertools
import json
import logging
from json.decoder import JSONDecodeError
from typing import List

import resource_loaders
from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.classifier import Classifier
from anomaly_detection.db import DBConnector
from anomaly_detection.evaluator import Evaluator
from anomaly_detection.model_trainer import ModelTrainer
from anomaly_detection.types import TrafficReader


class HypertuneSettings(dict):
    pass


class Hypertuner:
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, only_index: int = None):
        self.db = db
        self.traffic_reader = traffic_reader
        self.only_index = only_index

    def _load_file(self, path: str) -> HypertuneSettings:
        with open(path, "r") as f:
            try:
                obj = json.load(f)
            except JSONDecodeError as e:
                raise ValueError("Invalid json, cannot read hypertune settings from %s" % path) from e
        return HypertuneSettings(obj)

    def start(self, path: str):
        settings = self._load_file(path)
        transformer_combinations = self.parse_transformer_combinations(settings)
        fe_name = settings["feature_extractor"]["name"]
        de_name = settings["decision_engine"]["name"]
        # combine all specified parameters
        # it is important that at first the feature extractors are varied, so that the features
        # are stored in the db and can be reused later
        param_lists = []
        for de_parameter, values in settings["decision_engine"]["parameters"].items():
            param_lists.append(list(itertools.product([de_parameter], values)))
        for fe_parameter, values in settings["feature_extractor"]["parameters"].items():
            param_lists.append(list(itertools.product([fe_parameter], values)))

        hyperparam_combinations = list(itertools.product(
            list(itertools.product(*param_lists)), transformer_combinations)
        )
        total = len(hyperparam_combinations)
        for i, hyperparams in enumerate(hyperparam_combinations):
            args, transformers = hyperparams
            if self.only_index is not None and self.only_index != i:
                continue
            # flatten the parameters to a cli-like list
            # e.g.: [("kernel": "poly"), ("c":1)] => ["kernel","poly","c","1"]
            flat_args = []
            for arg in args:
                if arg[1] is None:
                    continue
                elif type(arg[1]) is list:
                    flat_args += [arg[0]] + arg[1]
                else:
                    flat_args += [arg[0], str(arg[1])]

            self.exec_hyperparam_config(de_name, fe_name, transformers, flat_args, 1 + i, total)

    def parse_transformer_combinations(self, settings):
        json_node = settings["transformers"]
        if type(json_node) is not list:
            raise ValueError("Expected transformers definition to be a list, but got: %s" % type(json_node))
        if len(json_node) == 0 or type(json_node[0]) == str:
            if sum([0 if type(item) else 1 for item in json_node]) > 0:
                raise ValueError("Expected a list pure strings, if the first transformer element is a string.")
            return [json_node]
        return json_node

    def exec_hyperparam_config(self, de_name, fe_name, transformers: List[str], train_args: List[str], i, total):
        try:
            fe, de, unknown_args, subparsers = resource_loaders.create_fe_and_de(
                de_name=de_name, fe_name=fe_name, args=train_args)
            if len(unknown_args) != 0:
                raise ValueError("Wrong parameters! %s" % unknown_args)
            logging.info("Start executing %s/%s: %s; transformers: %s", i, total, train_args, transformers)
            transformers = resource_loaders.build_transformers(transformers)
            ad_model = AnomalyDetectorModel(de, fe, transformers)
            model_trainer = ModelTrainer(self.db, self.traffic_reader, ad_model)

            model_trainer.start_training(store_features=True, load_features=True)

            model_id = model_trainer.model_id
            classifier = Classifier(self.db, self.traffic_reader, model_id=model_id)
            classification_id = classifier.start_classification()

            evaluator = Evaluator(self.db, self.traffic_reader)
            results = evaluator.evaluate(classification_id)
            logging.info("Finished %s/%s: %s Results: %s", i, total, train_args, results["all"]["total"])
        except Exception as e:
            logging.error("Error occured for %s", train_args, exc_info=e)
