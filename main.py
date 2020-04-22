#!/usr/bin/python3.8

import argparse
import pandas
import os
import dataset_utils.cic_ids_2017 as cic2017
from anomaly_detection.anomaly_detector import AnomalyDetector
from anomaly_detection.evaluator import Evaluator
import datetime

DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/MachineLearningCVE/")

classified = 0
attacks = 0


def main():
    parser = argparse.ArgumentParser(prog='PROG')
    subparsers = parser.add_subparsers(
        help='sub-command help', dest="subparser_name")
    
    parser.add_argument("--dataset-path", "-dp", dest="dataset_path", help="Path of the dataset", default=DATASET_PATH)

    parser_simulate = subparsers.add_parser(
        "simulate", help='Feed traffic from a dataset and detect anomalies.')
    parser_simulate.add_argument(
        '--output', "-o",  type=str, help='Log file where the predictions will be written into', default=f"log-{datetime.datetime.now()}.csv")

    parser_evaluate = subparsers.add_parser(
        "evaluate", help='Generate an evaluation report from a log file.')
    parser_evaluate.add_argument(
        "--logfile", "-l", type=str, help="Log file with classifications", required=True)
    parsed = parser.parse_args()

    reader = cic2017.Reader(parsed.dataset_path)
    if parsed.subparser_name == "simulate":
        ad = AnomalyDetector(log_path = parsed.output)
        evaluator = Evaluator(ad, reader)
        evaluator.start_train_test()
    elif parsed.subparser_name == "evaluate":
        ad = AnomalyDetector(log_path = parsed.logfile)
        evaluator = Evaluator(ad, reader)
        evaluator.evaluate()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
