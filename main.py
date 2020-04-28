#!/usr/bin/python3

import argparse
import pandas
import os
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection.anomaly_detector import *
import anomaly_detection.one_class_svm as one_class_svm
import anomaly_detection.local_outlier_factor as local_outlier_factor
from anomaly_detection.evaluator import *
from anomaly_detection.db import DBConnector
import datetime
import logging

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/MachineLearningCVE/")

DECISION_ENGINES = {
    "one_class_svm": (one_class_svm.OneClassSVMDE, one_class_svm.create_parser),
    "local_outlier_factor": (local_outlier_factor.LocalOutlierFactorDE, local_outlier_factor.create_parser)
}


def main():
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        '--db', type=str,
        help='Database file where the predictions will be written into',
        default="classifications.db"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_simulate = subparsers.add_parser(
        "simulate", help='Feed traffic from a dataset and detect anomalies.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_simulate.add_argument(
        "--decision-engine", type=str, dest="decision_engine", default=list(DECISION_ENGINES.keys())[0], choices=DECISION_ENGINES.keys(),
        help="Choose which algorithm will be used for classifying anomalies."
    )
    parser_simulate.add_argument(
        "--id", type=str, default=f"{datetime.datetime.now()}", help="Id of the classification."
    )
    add_common_arguments(parser_simulate)

    parser_evaluate = subparsers.add_parser(
        "evaluate", help='Generate an evaluation report in JSON format from a prediction log.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_evaluate.add_argument(
        "--output", "-o", type=str, required=True, help="File where the report will be written into. It is not allowed to exist yet."
    )
    parser_evaluate.add_argument(
        "--id", type=str, required=True, help="Id of the classification that will be evaluated."
    )
    add_common_arguments(parser_evaluate)

    parser_list_de = subparsers.add_parser(
        "list-de", help="Lists the available decision engines")
    parser_list_de.add_argument("--short", "-s", help="Only list the names of the decision engines, without usage details", action="store_true")

    parser_list_cl = subparsers.add_parser(
        "list-classifications", help="Lists the classifications")


    parsed, unknown = parser.parse_known_args()
    try:
        handle_parsed_arguments(parsed, unknown)
    except ValueError as e:
        parser.print_help()
        print(str(e))


def add_common_arguments(subparser):
    subparser.add_argument("--dataset-path", "-d", dest="dataset_path",
                           help="Path of the dataset", default=DATASET_PATH)

def handle_parsed_arguments(parsed, unknown):
    if parsed.command == "simulate":
        reader = cic2017.Reader(parsed.dataset_path)
        de = create_decision_engine(parsed.decision_engine, unknown)
        db = DBConnector(db_path=parsed.db)
        ad = AnomalyDetector(
            db, classification_id=parsed.id,  decision_engine=de)
        simulator = Simulator(ad, reader)
        simulator.start_train_test()
    elif parsed.command == "evaluate":
        reader = cic2017.Reader(parsed.dataset_path)
        db = DBConnector(db_path=parsed.db)
        evaluator = Evaluator(db, reader, parsed.output)
        evaluator.evaluate(classification_id=parsed.id)
    elif parsed.command == "list-de":
        for name in DECISION_ENGINES.keys():
            if parsed.short:
                print(name)
            else:
                _, de_parser_creator = DECISION_ENGINES[name]
                print(f"\n>>> {name} <<<\n")
                parser = de_parser_creator(name)
                parser.print_help()
    elif parsed.command == "list-classifications":
        db = DBConnector(db_path=parsed.db)
        info = db.get_classification_info()
        print(info)

def create_decision_engine(name, args):
    if name not in DECISION_ENGINES:
        raise ValueError(
            f"{name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES}")

    de_class, de_create_parser = DECISION_ENGINES[name]
    parser = de_create_parser(prog_name=name)
    parsed, unknown = parser.parse_known_args(args)
    if len(unknown) != 0:
        raise ValueError(
            f"{parser.format_help()}\nInvalid parameter(s): {', '.join(unknown)}")

    decision_engine_instance = de_class(parsed)
    return decision_engine_instance


if __name__ == "__main__":
    main()
