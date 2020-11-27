import unittest

from canids.dataset_utils.packet_label_associator import FlowIDFormatter

FLOW_IDS = {
    ("20.1.20.1", "172.168.1.1", 443, 80, 7): [
        "20.1.20.1-172.168.1.1-443-80-7",
        "172.168.1.1-20.1.20.1-80-443-7",
    ],
    ("0", "0", 0, 0, 0): ["0-0-0-0-0", "0-0-0-0-0"],
    ("A-B", "B-A", 300000, 20, 0): ["A-B-B-A-300000-20-0", "B-A-A-B-20-300000-0"],
}


class PcapUtilsTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_make_flow_ids(self):
        id_formatter = FlowIDFormatter()
        for data, exp in FLOW_IDS.items():
            flow_ids = [
                id_formatter.format_flow_id(*data),
                id_formatter.format_flow_id(*data, reverse=True),
            ]
            self.assertEqual(
                flow_ids,
                exp,
                msg="Expected flow %s to have ids %s, but got %s"
                % (data, exp, flow_ids),
            )


if __name__ == "__main__":
    unittest.main()
