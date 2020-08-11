import itertools
import json
import logging
from concurrent.futures.process import ProcessPoolExecutor
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
    def __init__(self, db: DBConnector, traffic_reader: TrafficReader, max_workers=2):
        self.db = db
        self.traffic_reader = traffic_reader
        self.max_workers = max_workers

    def _load_file(self, path: str) -> HypertuneSettings:
        with open(path, "r") as f:
            obj = json.load(f)
        return HypertuneSettings(obj)

    def start(self, path: str):
        settings = self._load_file(path)
        print(settings)
        transformers = settings["transformers"]
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

        with ProcessPoolExecutor(self.max_workers) as executor:
            last_future = None
            for args in itertools.product(*param_lists):
                flat_args = []
                for arg in args:
                    flat_args += [arg[0], str(arg[1])]
                last_future = executor.submit(self.exec_hyperparam_config, de_name, fe_name, transformers, flat_args)
            last_future.result()

    def exec_hyperparam_config(self, de_name, fe_name, transformers: List[str], train_args: List[str]):
        logging.info("Exec %s" % train_args)
        fe, de, unknown_args, subparsers = resource_loaders.create_fe_and_de(
            de_name=de_name, fe_name=fe_name, args=train_args)
        if len(unknown_args) != 0:
            raise ValueError("Wrong parameters! %s" % unknown_args)
        transformers = resource_loaders.build_transformers(transformers)
        ad_model = AnomalyDetectorModel(de, fe, transformers)
        model_trainer = ModelTrainer(self.db, self.traffic_reader, ad_model)

        model_trainer.start_training(store_features=True, load_features=True)

        model_id = model_trainer.model_id
        classifier = Classifier(self.db, self.traffic_reader, model_id=model_id)
        classification_id = classifier.start_classification()

        evaluator = Evaluator(self.db, self.traffic_reader)
        evaluator.evaluate(classification_id)
