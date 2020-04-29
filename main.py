#!/usr/bin/python3

import argparse
import pandas
import os
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection.anomaly_detector import *
import anomaly_detection.one_class_svm as one_class_svm
import anomaly_detection.local_outlier_factor as local_outlier_factor
from anomaly_detection.simulator import Simulator
from anomaly_detection.evaluator import Evaluator
from anomaly_detection.db import DBConnector
import datetime
import logging
import typing as t

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/MachineLearningCVE/")

DECISION_ENGINES = {
    "one_class_svm": (one_class_svm.OneClassSVMDE, one_class_svm.create_parser),
    "local_outlier_factor": (local_outlier_factor.LocalOutlierFactorDE, local_outlier_factor.create_parser)
}


def main():
    logging.basicConfig(level=logging.DEBUG)
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

        parser.add_argument(
            '--db', type=str,
            help='Database file where the predictions will be written into',
            default="classifications.db"
        )
        self.subparsers = parser.add_subparsers(dest="command", required=True)

        parser_simulate = self._create_subparser(
            "simulate", help='Feed traffic from a dataset and detect anomalies.', )
        parser_simulate.add_argument(
            "--decision-engine", type=str, dest="decision_engine", default=list(DECISION_ENGINES.keys())[0], choices=DECISION_ENGINES.keys(),
            help="Choose which algorithm will be used for classifying anomalies."
        )
        parser_simulate.add_argument(
            "--id", type=str, default=f"{datetime.datetime.now()}", help="Id of the classification."
        )
        self._add_common_arguments(parser_simulate)

        parser_evaluate = self._create_subparser(
            "evaluate", help='Generate an evaluation report in JSON format from a prediction log.')
        parser_evaluate.add_argument(
            "--output", "-o", type=str, required=True, help="File where the report will be written into. It is not allowed to exist yet."
        )
        parser_evaluate.add_argument(
            "--id", type=str, required=True, help="Id of the classification that will be evaluated."
        )
        self._add_common_arguments(parser_evaluate)

        parser_list_de = self._create_subparser(
            "list-de", help="Lists the available decision engines")
        parser_list_de.add_argument(
            "--short", "-s", help="Only list the names of the decision engines, without usage details", action="store_true")

        parser_list_cl = self._create_subparser(
            "list-classifications", help="Lists the classifications")

    def _create_subparser(self, name: str, help: str):
        sp = self.subparsers.add_parser(
            name, help=help, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.subparser_references[name] = sp
        return sp

    def _add_common_arguments(self, subparser):
        subparser.add_argument("--dataset-path", "-d", dest="dataset_path",
                               help="Path of the dataset", default=DATASET_PATH)

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

    def simulate(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        reader = cic2017.Reader(args.dataset_path)
        de = self._create_decision_engine(args.decision_engine, unknown)
        db = DBConnector(db_path=args.db)
        ad = AnomalyDetector(
            db, classification_id=args.id,  decision_engine=de)
        simulator = Simulator(ad, reader)
        simulator.start_train_test()

    def _create_decision_engine(self, name, args):
        if name not in DECISION_ENGINES:
            raise ParsingException(
                f"{name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES}")

        de_class, de_create_parser = DECISION_ENGINES[name]
        parser = de_create_parser(prog_name=name)
        parsed, unknown = parser.parse_known_args(args)
        self._check_unknown_args(unknown, expected_len=0, subparser=parser)

        decision_engine_instance = de_class(parsed)
        return decision_engine_instance

    def list_de(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        for name in DECISION_ENGINES.keys():
            if args.short:
                print(name)
            else:
                _, de_parser_creator = DECISION_ENGINES[name]
                print(f"\n>>> {name} <<<\n")
                parser = de_parser_creator(name)
                parser.print_help()

    def list_classifications(self, args: argparse.Namespace, unknown: t.Sequence[str]):
        self._check_unknown_args(unknown, expected_len=0)
        db = DBConnector(db_path=args.db, init_if_not_exists=False)
        info = db.get_classification_info()
        print(info)

    def _check_unknown_args(self, unknown: t.Sequence[str], expected_len, subparser: argparse.ArgumentParser = None):
        if len(unknown) != expected_len:
            if subparser is not None:
                subparser.print_usage()
            raise ParsingException("Invalid arguments: %s" % " ".join(unknown))

    def parse_and_exec(self):
        parser = self.cli_parser.parser
        parsed_args, unknown = parser.parse_known_args()
        fn_name = parsed_args.command.replace("-", "_")
        fn = getattr(self, fn_name)
        try:
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
