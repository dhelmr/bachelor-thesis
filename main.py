#!/usr/bin/python3

import argparse
import logging
import os
import typing as t

import pandas

import anomaly_detection.local_outlier_factor as local_outlier_factor
import anomaly_detection.one_class_svm as one_class_svm
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.classifier import Classifier, CLASSIFICATION_ID_AUTO_GENERATE
from anomaly_detection.db import DBConnector
from anomaly_detection.evaluator import Evaluator
from anomaly_detection.model_trainer import ModelTrainer
from anomaly_detection.preprocessors import StandardScalerPreprocessor, MinxMaxScalerPreprocessor

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/MachineLearningCVE/")

DECISION_ENGINES = {
    "one_class_svm": (one_class_svm.OneClassSVMDE, one_class_svm.create_parser),
    "local_outlier_factor": (local_outlier_factor.LocalOutlierFactorDE, local_outlier_factor.create_parser)
}

PREPROCESSORS = {
    "minmax_scaler": MinxMaxScalerPreprocessor,
    "standard_scaler": StandardScalerPreprocessor
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
        parser_train.add_argument('--preprocessor', '-p', type=str, nargs='+', dest="preprocessors",
                                  choices=list(PREPROCESSORS.keys()),
                                  help='Specifies one or more preprocessors that are applied before calling the decision engine.')

        self._add_model_param(parser_train)
        self._add_decision_engine_param(parser_train)
        self._add_dataset_param(parser_train)

        parser_classify = self._create_subparser(
            "classify", help='Feed traffic from a dataset and detect anomalies.', )
        parser_classify.add_argument(
            "--id", type=str, default=CLASSIFICATION_ID_AUTO_GENERATE,
            help=f"Id of the classification. If {CLASSIFICATION_ID_AUTO_GENERATE} is specified, a new id will be auto-generated."
        )
        self._add_model_param(parser_classify)
        self._add_dataset_param(parser_classify)

        parser_evaluate = self._create_subparser(
            "evaluate", help='Generate an evaluation report in JSON format from a prediction log.')
        parser_evaluate.add_argument(
            "--output", "-o", type=str, required=True,
            help="File where the report will be written into. It is not allowed to exist yet."
        )
        parser_evaluate.add_argument(
            "--id", type=str, required=True, help="Id of the classification that will be evaluated."
        )
        self._add_dataset_param(parser_evaluate)

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

        parser_list_models = self._create_subparser("list-models", help="List available models.")

    def _create_subparser(self, name: str, help: str):
        sp = self.subparsers.add_parser(
            name, help=help, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.subparser_references[name] = sp
        self._add_common_params(sp)
        return sp

    def _add_dataset_param(self, subparser):
        subparser.add_argument("--dataset-path", "-d", dest="dataset_path",
                               help="Path of the dataset", default=DATASET_PATH)

    def _add_decision_engine_param(self, subparser):
        subparser.add_argument(
            "--decision-engine", type=str, dest="decision_engine", default=list(DECISION_ENGINES.keys())[0],
            choices=DECISION_ENGINES.keys(),
            help="Choose which algorithm will be used for classifying anomalies."
        )

    def _add_model_param(self, subparser):
        subparser.add_argument(
            "--model-id", "-m", help="ID of the model.", required=True, type=str, dest="model_id"
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

    def evaluate(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        reader = cic2017.Reader(args.dataset_path)
        db = DBConnector(db_path=args.db)
        evaluator = Evaluator(db, reader, args.output)
        evaluator.evaluate(classification_id=args.id)

    def train(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        reader = cic2017.Reader(args.dataset_path)
        de = self._create_decision_engine(args.decision_engine, unknown)
        db = DBConnector(db_path=args.db)
        preprocessors = self._build_preprocessors(args.preprocessors)
        ad = AnomalyDetectorModel(de, preprocessors)
        trainer = ModelTrainer(db, reader, anomaly_detector=ad, model_id=args.model_id)
        trainer.start_training()

    def classify(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        reader = cic2017.Reader(args.dataset_path)
        db = DBConnector(db_path=args.db)
        simulator = Classifier(db, reader, model_id=args.model_id)
        simulator.start_classification(args.id)

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

    def list_classifications(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_all_classifications(with_count=args.count)
        self._print_dataframe(info)

    def list_models(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_all_models()
        # TODO: don't drop pickle dump but instead read model-specific parameters from it
        info.drop(columns="pickle_dump", inplace=True)
        self._print_dataframe(info)

    def _print_dataframe(self, df: pandas.DataFrame):
        if len(df) == 0:
            print("<None>")
        else:
            print(df)

    def _create_decision_engine(self, name, args):
        if name not in DECISION_ENGINES:
            raise ParsingException(
                f"{name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES.keys()}")
        de_class, de_create_parser = DECISION_ENGINES[name]
        parser = de_create_parser(prog_name=name)
        parsed, unknown = parser.parse_known_args(args)
        self._check_unknown_args(unknown, expected_len=0, subparser=parser)
        decision_engine_instance = de_class(parsed)
        return decision_engine_instance

    def _build_preprocessors(self, names: t.Sequence[str]):
        preprocessors = list()
        for name in names:
            if name not in PREPROCESSORS:
                raise ParsingException(
                    f"{name} is not a valid preprocessor. Please specify one of: {DECISION_ENGINES.keys()}")
            preprocessors.append(PREPROCESSORS[name]())
        return preprocessors

    def _check_unknown_args(self, unknown: t.Sequence[str], expected_len, subparser: argparse.ArgumentParser = None):
        if len(unknown) != expected_len:
            if subparser is not None:
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
