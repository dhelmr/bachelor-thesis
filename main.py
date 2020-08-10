#!/usr/bin/python3

import argparse
import logging
import os
import typing as t

import pandas

import anomaly_detection.local_outlier_factor as local_outlier_factor
import anomaly_detection.one_class_svm as one_class_svm
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection import model_trainer
from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.classifier import Classifier, CLASSIFICATION_ID_AUTO_GENERATE
from anomaly_detection.db import DBConnector
from anomaly_detection.evaluator import Evaluator
from anomaly_detection.feature_extractors.basic_netflow_extractor import BasicNetflowFeatureExtractor
from anomaly_detection.feature_extractors.basic_packet_feature_extractor import BasicPacketFeatureExtractor
from anomaly_detection.feature_extractors.doc2vec_packets import PacketDoc2Vec
from anomaly_detection.feature_extractors.netflow_doc2vec import NetflowDoc2Vec
from anomaly_detection.feature_extractors.testing_extractor import TestingFeatureExtractor, DummyPreprocessor, \
    DummyTrafficGenerator
from anomaly_detection.model_trainer import ModelTrainer
from anomaly_detection.transformers import StandardScalerTransformer, MinxMaxScalerTransformer
from anomaly_detection.types import DatasetUtils, FeatureExtractor, DecisionEngine
from dataset_utils.cic_ids_2017 import CICIDS2017Preprocessor

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/")

DECISION_ENGINES = {
    "one_class_svm": (one_class_svm.OneClassSVMDE, one_class_svm.create_parser),
    "local_outlier_factor": (local_outlier_factor.LocalOutlierFactorDE, local_outlier_factor.create_parser)
}

TRANSFORMERS = {
    "minmax_scaler": MinxMaxScalerTransformer,
    "standard_scaler": StandardScalerTransformer
}

FEATURE_EXTRACTORS = {
    "basic_netflow": BasicNetflowFeatureExtractor,
    "basic_packet_info": BasicPacketFeatureExtractor,
    "doc2vec_packet": PacketDoc2Vec,
    "doc2vec_flows": NetflowDoc2Vec,
    "test": TestingFeatureExtractor
}

DATASET_UTILS = {
    "cic-ids-2017": DatasetUtils(cic2017.CIC2017TrafficReader, CICIDS2017Preprocessor),
    "test": DatasetUtils(DummyTrafficGenerator, DummyPreprocessor)
}


def main():
    logging.basicConfig(level=logging.INFO)
    cli_parser = CLIParser()
    cmd_executor = CommandExecutor(cli_parser)
    cmd_executor.parse_and_exec()


class CLIParser:
    """
    Wraps argparse.ArgumentParser and allows easy access to subparsers
    """

    def __init__(self):
        self.subparser_references = {}
        self.parser: argparse.ArgumentParser
        self._create_cli_parser()

    def _create_cli_parser(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.parser = parser
        self.subparsers = parser.add_subparsers(dest="command")

        parser_train = self._create_subparser(
            "train",
            help="Creates a classification model from analyzing normal traffic and stores it in the database."
        )
        parser_train.add_argument('--transformers', '-t', type=str, nargs='+', dest="transformers",
                                  choices=list(TRANSFORMERS.keys()), default=[],
                                  help='Specifies one or more transformers that are applied before calling the decision engine.')
        parser_train.add_argument('--feature-extractor', '-f', type=str, dest="feature_extractor",
                                  choices=list(FEATURE_EXTRACTORS.keys()), default=list(FEATURE_EXTRACTORS.keys())[0],
                                  help="Specifies the feature extractor that is used to generate features from the raw network traffic.")

        parser_train.add_argument(
            "--model-id", "-m",
            help=f"ID of the model. If {model_trainer.MODEL_ID_AUTO_GENERATE} is used, the model ID will be auto-generated.",
            type=str, dest="model_id", default=model_trainer.MODEL_ID_AUTO_GENERATE
        )
        self._add_decision_engine_param(parser_train)
        self._add_dataset_path_param(parser_train)

        parser_classify = self._create_subparser(
            "classify", help='Feed traffic from a dataset and detect anomalies.', )
        parser_classify.add_argument(
            "--id", type=str, default=CLASSIFICATION_ID_AUTO_GENERATE,
            help=f"Id of the classification. If {CLASSIFICATION_ID_AUTO_GENERATE} is specified, a new id will be auto-generated."
        )
        parser_classify.add_argument(
            "--model-id", "-m", help="ID of the model.", required=True, type=str, dest="model_id"
        )
        self._add_dataset_path_param(parser_classify)

        parser_evaluate = self._create_subparser(
            "evaluate", help="Generate an evaluation report in JSON format from a prediction log.")
        parser_evaluate.add_argument(
            "--output", "-o", type=str, required=True,
            help="File where the report will be written into. It is not allowed to exist yet."
        )
        parser_evaluate.add_argument(
            "--id", type=str, required=True, help="Id of the classification that will be evaluated."
        )
        parser_evaluate.add_argument(
            "--force-overwrite", "-f", default=False, action="store_true",
            help="Overwrite the report file, if it already exists."
        )
        parser_evaluate.add_argument(
            "--filter-names", default=None, nargs="+",
            dest="filter_names", help="Filters the traffic sequence names that are to be evaluated."
        )
        self._add_dataset_path_param(parser_evaluate)

        parser_list_de = self._create_subparser(
            "list-de", help="Lists the available decision engines")
        parser_list_de.add_argument(
            "--short", "-s", help="Only list the names of the decision engines, without usage details",
            action="store_true")

        parser_list_cl = self._create_subparser(
            "list-classifications", help="Lists all anomaly classifications that were previously run.")
        parser_list_cl.add_argument(
            "--count", "-c", help="Additionally list the number of records for each classification.",
            action="store_true"
        )

        parser_list_fe = self._create_subparser(
            "list-fe", help="Lists all available feature extractors"
        )
        parser_list_fe.add_argument(
            "--short", "-s", help="Only list the names of the decision engines, without usage details",
            action="store_true")

        preprocess = self._create_subparser(
            "preprocess", help="Preprocesses a dataset so that it can be used for evaluation afterwards."
        )
        self._add_dataset_path_param(preprocess)

        parser_list_models = self._create_subparser("list-models", help="List available models.")

    def _create_subparser(self, name: str, help: str):
        sp = self.subparsers.add_parser(
            name, help=help, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.subparser_references[name] = sp
        self._add_common_params(sp)
        return sp

    def _add_dataset_path_param(self, subparser):
        subparser.add_argument(
            "--dataset", "-d", type=str, dest="dataset", default=list(DATASET_UTILS.keys())[0],
            help=f"The name of the dataset. Choose one of: {list(DATASET_UTILS.keys())}",
            choices=list(DATASET_UTILS.keys())
        )
        subparser.add_argument("--src", dest="dataset_path",
                               help="Path of the dataset", default=DATASET_PATH)
        subparser.add_argument("--subset", dest="dataset_subset",
                               help="Predefined subset of the dataset", default="default")

    def _add_decision_engine_param(self, subparser):
        subparser.add_argument(
            "--decision-engine", type=str, dest="decision_engine", default=list(DECISION_ENGINES.keys())[0],
            choices=DECISION_ENGINES.keys(),
            help="Choose which algorithm will be used for classifying anomalies."
        )

    def _add_common_params(self, subparser):
        subparser.add_argument(
            '--db', type=str,
            help='Database file where the classifications are stored.',
            default="classifications.db"
        )
        subparser.add_argument(
            '--debug', "--verbose", action="store_true",
            help='Will produce verbose output that is useful for debugging'
        )

    def get_subparser(self, subparser_name) -> argparse.ArgumentParser:
        """argparse does not allow directly accessing its subparsers, so this little helper method does it."""
        if subparser_name not in self.subparser_references:
            raise ValueError("Subparser %s does not exist!" % subparser_name)
        return self.subparser_references[subparser_name]


class CommandExecutor:
    def __init__(self, cli_parser: CLIParser):
        self.cli_parser: CLIParser = cli_parser

    def train(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        reader = self._get_dataset_reader(args)
        db = DBConnector(db_path=args.db)
        transformers = self._build_transformers(args.transformers)
        feature_extractor, de = self._create_fe_and_de(de_name=args.decision_engine,
                                                       fe_name=args.feature_extractor,
                                                       args=unknown)
        ad = AnomalyDetectorModel(de, feature_extractor, transformers)
        trainer = ModelTrainer(db, reader, anomaly_detector=ad, model_id=args.model_id)
        trainer.start_training()

    def classify(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        reader = self._get_dataset_reader(args)
        db = DBConnector(db_path=args.db)
        simulator = Classifier(db, reader, model_id=args.model_id)
        simulator.start_classification(args.id)

    def evaluate(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        reader = self._get_dataset_reader(args)
        db = DBConnector(db_path=args.db)
        evaluator = Evaluator(db, reader, args.output, args.force_overwrite)
        evaluator.evaluate(classification_id=args.id, filter_traffic_names=args.filter_names)

    def list_de(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        for name in DECISION_ENGINES.keys():
            if args.short:
                print(name)
            else:
                _, de_parser_creator = DECISION_ENGINES[name]
                print(f">>> {name} <<<")
                parser = de_parser_creator(name)
                parser.print_help()
                print("\n")

    def list_fe(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        for name in FEATURE_EXTRACTORS.keys():
            if args.short:
                print(name)
            else:
                print(f">>> {name} <<<")
                parser = argparse.ArgumentParser()
                FEATURE_EXTRACTORS[name].init_parser(parser)
                parser.print_help()
                print("\n")

    def preprocess(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        preprocessor = self._get_dataset_utils(args.dataset).preprocessor()
        preprocessor.preprocess(args.dataset_path)

    def list_classifications(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_all_classifications(with_count=args.count)
        self._print_dataframe(info)

    def list_models(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_all_models()
        info["model"] = info["pickle_dump"].apply(self._format_model_dump)
        info.drop(columns=["pickle_dump", "decision_engine", "feature_extractor"], inplace=True)
        self._print_dataframe(info)

    def _format_model_dump(self, dump: str) -> str:
        try:
            model = AnomalyDetectorModel.deserialize(dump)
        except Exception as e:
            logging.error(e)
            return "(err: could not read)"
        de_info = str(model.decision_engine)
        fe_info = str(model.feature_extractor)
        return f"DE: {de_info}| FE: {fe_info}"

    def _print_dataframe(self, df: pandas.DataFrame):
        if len(df) == 0:
            print("<None>")
            return
        print(df.to_string())

    def _get_dataset_reader(self, args: argparse.Namespace):
        return self._get_dataset_utils(args.dataset).traffic_reader(args.dataset_path, args.dataset_subset)

    def _create_fe_and_de(self, fe_name: str,
                          de_name: str, args: t.Sequence[str]) -> t.Tuple[FeatureExtractor, DecisionEngine]:
        if fe_name not in FEATURE_EXTRACTORS:
            raise ParsingException(
                f"{fe_name} is not a valid feature extractor. Please specify one of: {FEATURE_EXTRACTORS.keys()}")
        feature_extractor_class = FEATURE_EXTRACTORS[fe_name]
        fe_parser = argparse.ArgumentParser(prog=f"Feature Extractor ({fe_name})")
        feature_extractor_class.init_parser(fe_parser)
        parsed, unknown = fe_parser.parse_known_args(args)
        feature_extractor = feature_extractor_class.init_by_parsed(parsed)

        if de_name not in DECISION_ENGINES:
            raise ParsingException(
                f"{de_name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES.keys()}")
        de_class, de_create_parser = DECISION_ENGINES[de_name]
        de_parser = de_create_parser(prog_name=f"Decision Engine ({de_name})")
        parsed, unknown = de_parser.parse_known_args(unknown)
        self._check_unknown_args(unknown, expected_len=0, subparsers=[fe_parser, de_parser])
        decision_engine_instance = de_class(parsed)
        return feature_extractor, decision_engine_instance

    def _build_transformers(self, names: t.Sequence[str]):
        transformers = list()
        for name in names:
            if name not in TRANSFORMERS:
                raise ParsingException(
                    f"{name} is not a valid transformer. Please specify one of: {TRANSFORMERS.keys()}")
            transformers.append(TRANSFORMERS[name]())
        return transformers

    def _get_dataset_utils(self, dataset_name: str) -> DatasetUtils:
        if dataset_name not in DATASET_UTILS:
            raise ParsingException(f"{dataset_name} is not a valid dataset.")
        return DATASET_UTILS[dataset_name]

    def _check_unknown_args(self, unknown: t.Sequence[str], expected_len,
                            subparsers: t.List[argparse.ArgumentParser] = []):
        if len(unknown) != expected_len:
            for subparser in subparsers:
                subparser.print_usage()
            raise ParsingException("Invalid arguments: %s" % " ".join(unknown))

    def handle_common_args(self, parsed_args):
        if parsed_args.debug == True:
            logging.basicConfig(force=True, level=logging.DEBUG)

    def parse_and_exec(self):
        parser = self.cli_parser.parser
        parsed_args, unknown = parser.parse_known_args()
        if parsed_args.command is None:
            parser.print_help()
            return

        fn_name = parsed_args.command.replace("-", "_")
        fn = getattr(self, fn_name)
        if fn is None:
            parser.print_help()
            print("Unknown command:", parsed_args.command)
            return
        try:
            self.handle_common_args(parsed_args)
            fn(parsed_args, unknown)
        except ParsingException as e:
            subparser = self.cli_parser.get_subparser(
                subparser_name=parsed_args.command)
            subparser.print_usage()
            print("\n", str(e))


class ParsingException(Exception):
    pass


if __name__ == "__main__":
    main()
