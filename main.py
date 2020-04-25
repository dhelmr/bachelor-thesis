#!/usr/bin/python3.8

import argparse
import pandas
import os
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection.anomaly_detector import AnomalyDetector
from anomaly_detection.evaluator import *
import datetime
import logging

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/MachineLearningCVE/")


def main():
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    parser_simulate = subparsers.add_parser(
        "simulate", help='Feed traffic from a dataset and detect anomalies.')
    parser_simulate.add_argument(
        '--logfile', "-l",  type=str, required=True, help='Log file where the predictions will be written into', default=f"log-{datetime.datetime.now()}.csv")
    add_common_arguments(parser_simulate)

    parser_evaluate = subparsers.add_parser(
        "evaluate", help='Generate an evaluation report from a log file.')
    parser_evaluate.add_argument(
        "--logfile", "-l", type=str, help="Log file with classifications", required=True)
    parser_evaluate.add_argument(
        "--output", "-o", type=str, required=True, help="File where the report will be written into. It must not exist yet."
    )
    add_common_arguments(parser_evaluate)
    

    parsed, unknown = parser.parse_known_args()
    handle_parsed_arguments(parsed, unknown)

def add_common_arguments(subparser):
    subparser.add_argument("--dataset-path", "-d", dest="dataset_path", help="Path of the dataset", default=DATASET_PATH)
 
def handle_parsed_arguments(parsed, unknown):
    print(unknown)
    reader = cic2017.Reader(parsed.dataset_path)
    ad = AnomalyDetector(log_path=parsed.logfile)
    if parsed.command == "simulate":
        simulator = Simulator(ad, reader)
        simulator.start_train_test()
    elif parsed.command == "evaluate":
        evaluator = Evaluator(ad, reader, parsed.output)
        evaluator.evaluate()


if __name__ == "__main__":
    main()
