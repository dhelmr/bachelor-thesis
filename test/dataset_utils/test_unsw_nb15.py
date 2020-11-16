import os
import unittest

import pandas

from canids.dataset_utils.unsw_nb15 import UNSWNB15Preprocessor, read_packet_labels, iter_pcaps
from canids.types import TrafficType

TEST_DATASET = os.path.join(os.path.dirname(__file__), "test_data")
VALIDATION_PCAP = os.path.join(TEST_DATASET, "01", "1.pcap")


class UnswNb15Tests(unittest.TestCase):
    def test_subset_generation(self):
        preprocessor = UNSWNB15Preprocessor()

        ranges = preprocessor._make_ranges(TEST_DATASET)
        for pcap in iter_pcaps(TEST_DATASET, yield_relative=True, quiet=True):
            try:
                validate_ranges(pcap, ranges)
            except AssertionError as e:
                raise AssertionError("Failed to verify pcap %s" % pcap) from e


def validate_ranges(pcap, ranges):
    full_pcap_path = os.path.join(TEST_DATASET, pcap)
    labels = read_packet_labels(full_pcap_path)
    if pcap not in ranges["benign"]:
        raise AssertionError("pcap %s not existent in subsets" % pcap)
    match_ranges_with_labels(labels, ranges["benign"][pcap])


def match_ranges_with_labels(labels: pandas.DataFrame, ranges):
    index = 0
    for _, row in labels.iterrows():
        traffic_type = row["traffic_type"]
        benign_counts = 0
        for r in ranges:
            if traffic_type is TrafficType.ATTACK and in_range(index, range_start=r[0], range_end=r[1]):
                raise AssertionError("Index %s is of type %s, but found in range %s" % (index, traffic_type, r))
            if traffic_type is TrafficType.BENIGN and in_range(index, range_start=r[0], range_end=r[1]):
                benign_counts += 1
        if traffic_type is TrafficType.BENIGN and benign_counts != 1:
            raise AssertionError(
                "Index %s is of type %s, but was matched by %s ranges." % (index, traffic_type, benign_counts))
        index += 1


def in_range(index, range_start, range_end):
    if range_end == "end":
        return range_start <= index
    else:
        return range_start <= index < range_end


if __name__ == '__main__':
    unittest.main()
    pass
