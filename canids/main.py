#!/usr/bin/python3

import argparse
import logging
import sys
import typing as t

import pandas

from canids import model_trainer
from canids import resource_loaders
from canids.anomaly_detector import AnomalyDetectorModel
from canids.classifier import Classifier, CLASSIFICATION_ID_AUTO_GENERATE
from canids.db import DBConnector
from canids.evaluator import Evaluator
from canids.hypertuner import Hypertuner
from canids.model_info import get_info
from canids.model_trainer import ModelTrainer
from canids.resource_loaders import DECISION_ENGINES, TRANSFORMERS, FEATURE_EXTRACTORS, DATASET_UTILS
from canids.types import DatasetUtils, ParsingException
from canids.visualize import EvaluationsVisualizer


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
        parser_train.add_argument("--store-features", dest="store_features", action="store_true",
                                  help="Stores the extraced features in the database, so that they can be reused later.")
        parser_train.add_argument("--load-features", dest="load_features", action="store_true",
                                  help="Loads features from a previous run, instead of executing the feature extractor."
                                       "This is only possible if the feature extractor ran before with this exact"
                                       " configuration and the traffic input is consistent.")

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
            "--output", "-o", type=str, required=False, default=None,
            help="File where the report will be written into. It is not allowed to exist yet if force overwrite is not set."
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
        parser_list_models.add_argument("--model", "-m", default=None, help="Filter information by model id.")

        parser_list_evaluations = self._create_subparser("list-evaluations", help="Prints evaluations.")
        parser_list_evaluations.add_argument("--model", "-m", default=None, help="Filter evaluations by model")
        parser_list_evaluations.add_argument("--id", default=None, help="Filter evaluations by classification id")

        db_migrate = self._create_subparser("migrate-db", help="Migrates database schema")

        hypertune = self._create_subparser(
            "hypertune", help="Hypertunes parameters of decision engine and feature extractor by running "
                              "the train->classify->evaluate pipeline multiple times. "
        )
        self._add_dataset_path_param(hypertune)
        hypertune.add_argument("-f", "--file", type=str, required=True,
                               help="Json file that specified which parameters are hypertuned.")
        hypertune.add_argument("--only-index", type=int, required=False, default=None,
                               help="if set, only the n-th hyperparameter configuration will be run.")

        visualize = self._create_subparser("visualize", help="Visualizes evaluations")
        visualize.add_argument("--model-part-name", required=True)
        visualize.add_argument("--hyperparameter", required=False, default=None)
        visualize.add_argument("--output-dir", "-o", default=".",
                               help="Directory where visualizations will be stored into.")
        visualize.add_argument("--detailed", action="store_true",
                               help="If set, more information per model is loaded from the db and displayed.")

        stats = self._create_subparser("stats", help="Print stats for a dataset")
        self._add_dataset_path_param(stats)

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
                               help="Path of the dataset, if not specified the dataset's default path is taken.",
                               default=None)
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
            default="sqlite.db"
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
        transformers = resource_loaders.build_transformers(args.transformers)
        feature_extractor, de, unknown, subparsers = resource_loaders.create_fe_and_de(de_name=args.decision_engine,
                                                                                       fe_name=args.feature_extractor,
                                                                                       args=unknown)
        self._check_unknown_args(unknown, expected_len=0, subparsers=subparsers)
        ad = AnomalyDetectorModel(de, feature_extractor, transformers)
        trainer = ModelTrainer(db, reader, anomaly_detector=ad, model_id=args.model_id)
        trainer.start_training(store_features=args.store_features, load_features=args.load_features)

    def classify(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        reader = self._get_dataset_reader(args)
        db = DBConnector(db_path=args.db)
        classifier = Classifier(db, reader, model_id=args.model_id)
        classifier.start_classification(args.id)

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
        dataset = self._get_dataset_utils(args.dataset)
        preprocessor = dataset.preprocessor()
        path = args.dataset_path
        if path is None:
            path = dataset.default_path
        preprocessor.preprocess(path, unknown)

    def list_classifications(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_all_classifications(with_count=args.count)
        self._print_dataframe(info)

    def list_models(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)

        if args.model is None:
            infos = db.get_model_infos()
            self._print_dataframe(infos)
        else:
            model_info = get_info(db, args.model)
            print(model_info.pretty())

    def hypertune(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        reader = self._get_dataset_reader(args)
        hypertuner = Hypertuner(db, reader, only_index=args.only_index)
        hypertuner.start(args.file)

    def stats(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        dataset = self._get_dataset_utils(args.dataset)
        if args.dataset_path is None:
            dataset_path = dataset.default_path
        else:
            dataset_path = args.dataset_path
        dataset.print_stats(dataset_path)

    def list_evaluations(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        df = db.get_evaluations()
        if args.model is not None:
            df = df[df["model_id"] == args.model]
        else:
            df = df[df["part_name"] == "all"]
        if args.id is not None:
            df = df[df["classification_id"] == args.id]
        filter_cols = ["classification_id", "decision_engine", "feature_extractor", "part_name", "precision", "mcc"]
        df = df[df["is_aggregated"] == 1]
        df = df[filter_cols]
        if len(df) == 0:
            print("None")
            return
        df["decision_engine"] = df["decision_engine"].apply(
            lambda text: str(text)[:10] + ("" if len(text) <= 10 else ".."))
        df["feature_extractor"] = df["feature_extractor"].apply(
            lambda text: str(text)[:10] + ("" if len(text) <= 10 else ".."))
        print(df.to_string())

    def visualize(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        visualizer = EvaluationsVisualizer(db, args.output_dir, detailed_info=args.detailed)
        visualizer.visualize(args.model_part_name, args.hyperparameter)

    def migrate_db(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        DBConnector(db_path=args.db, init_if_not_exists=True, migrate_if_needed=True)

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
        dataset = self._get_dataset_utils(args.dataset)
        if args.dataset_path is None:
            dataset_path = dataset.default_path
        else:
            dataset_path = args.dataset_path
        return dataset.traffic_reader(dataset_path, args.dataset_subset)

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
            sys.exit(126)
