import numpy as np


def calc_error(expected, observed):
    if expected == 0:
        return 0
    return abs(expected - observed) / expected


def make_report_dict(expected_packets, expected_flows, actual_packets):
    report = {
        "expected_flows": expected_flows,
        "expected_packets": expected_packets,
        "actual_packets": actual_packets,
        "difference": expected_flows - actual_packets,
        "error": calc_error(actual_packets, actual_packets),
    }
    for key, value in report.items():
        if isinstance(value, np.integer):
            report[key] = int(value)
        elif isinstance(value, np.floating):
            report[key] = float(value)
    return report
