import datetime
import itertools
import tempfile
import unittest
from typing import List, Tuple

import pandas
import pytz

from canids.dataset_utils.packet_label_associator import (
    PacketLabelAssociator,
    AdditionalInfo,
    COL_INFO,
    COL_START_TIME,
    COL_END_TIME,
    COL_FLOW_ID,
    COL_TRAFFIC_TYPE,
    COL_REVERSE_FLOW_ID,
)
from canids.types import TrafficType, Packet


class PacketLabelAssociatorTestImpl(PacketLabelAssociator):
    def __init__(self, flows, packets, *args, **kwargs):
        super().__init__(additional_cols=["attack_type"], *args, **kwargs)
        self.output_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.flows = flows
        self.packets = packets

    def _get_attack_flows(self, pcap_file):
        return self._find_attack_flows(self.flows)

    def make_flow_ids(self, packet: Packet) -> Tuple[str, str]:
        ts, buf = packet
        flow_id = str(buf)
        splitted = flow_id.split("-")
        if len(splitted) != 4:
            return None
        reverse_id = "-".join([splitted[2], splitted[3], splitted[0], splitted[1]])
        return flow_id, reverse_id

    def output_csv_file(self, pcap_file) -> str:
        return self.output_file.name

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        return cell_content

    def _unpack_additional_info(self, additional_info: AdditionalInfo) -> List[str]:
        return [additional_info if additional_info is not None else ""]

    def _open_pcap(self, pcap_file):
        return self.packets


attack_packets = {
    "Attack A": [
        (1000, "1-80-2-443"),
        (1010, "1-80-2-443"),
        (1020, "1-80-2-443"),
        (1040, "1-80-2-443"),
        (1050, "1-80-2-443"),
        (1051, "2-443-1-80"),
        (1052, "2-443-1-80"),
        (1999.99, "1-80-2-443"),
        (3109.2321323, "3-9000-2-443"),
    ],
    "Attack B": [(5033, "2-443-1-80"), (5030, "1-80-2-443")],
    "Attack C": [(3030, "1-80-2-443"), (1200, "2-443-4-1111"), (1500, "4-1111-2-443")],
    "Attack E": [(3002, "4-1111-2-443")],
    "Attack Z": [(2020, "5-443-6-666"), (2090, "5-443-6-666"), (2091, "6-666-5-443")],
}
benign_packets = [
    (2000, "2-443-1-80"),
    (2002, "1-80-2-443"),
    (6000, "2-443-5-5151"),
    (6100, "2-443-5-5151"),
    (6400, "5-5151-2-443"),
    (6500, "5-5151-2-443"),
    (6900, "2-443-5-5151"),
    (5900, "2-443-4-1111"),
    (3001, "6-666-5-443"),
    (3055, "5-443-6-666"),
    (3055, "5-443-6-666"),
    (100, "1-80-2-443"),  # not in any flow
    (200, "6-666-5-443"),  # not in any flow
    (9999, "A-B"),  # no valid flow
]
traffic_packets = list(
    sorted(
        list(itertools.chain(*attack_packets.values())) + benign_packets,
        key=lambda i: i[0],
    )
)


def make_ts(time):
    return datetime.datetime.fromtimestamp(time).astimezone(tz=pytz.utc)


class PacketLabelAssociatorTest(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.attack_flows = pandas.DataFrame(
            [
                [
                    "1-80-2-443",
                    "2-443-1-80",
                    make_ts(1000),
                    make_ts(1999.99),
                    "Attack A",
                    TrafficType.ATTACK,
                ],
                [
                    "1-80-2-443",
                    "2-443-1-80",
                    make_ts(2000),
                    make_ts(2900),
                    "",
                    TrafficType.BENIGN,
                ],
                [
                    "2-443-1-80",
                    "1-80-2-443",
                    make_ts(4000),
                    make_ts(5100),
                    "Attack B",
                    TrafficType.ATTACK,
                ],
                [
                    "2-443-3-9000",
                    "3-9000-2-443",
                    make_ts(1000),
                    make_ts(3800),
                    "Attack A",
                    TrafficType.ATTACK,
                ],
                [
                    "3-9000-2-443",
                    "2-433-3-9000",
                    make_ts(4000),
                    make_ts(4900),
                    "",
                    TrafficType.BENIGN,
                ],
                [
                    "2-443-3-9000",
                    "3-9000-2-443",
                    make_ts(6000),
                    make_ts(6950),
                    "Attack B",
                    TrafficType.ATTACK,
                ],
                [
                    "4-1111-2-443",
                    "2-443-4-1111",
                    make_ts(1000),
                    make_ts(1500),
                    "Attack C",
                    TrafficType.ATTACK,
                ],
                [
                    "2-443-4-1111",
                    "4-1111-2-443",
                    make_ts(3000),
                    make_ts(3002),
                    "Attack E",
                    TrafficType.ATTACK,
                ],
                [
                    "4-1111-2-443",
                    "2-443-4-1111",
                    make_ts(5000),
                    make_ts(6000),
                    "",
                    TrafficType.BENIGN,
                ],
                [
                    "2-443-1-80",
                    "1-80-2-443",
                    make_ts(3000),
                    make_ts(3100),
                    "Attack C",
                    TrafficType.ATTACK,
                ],
                [
                    "5-5151-2-443",
                    "2-443-5-5151",
                    make_ts(1000),
                    make_ts(2900),
                    "",
                    TrafficType.BENIGN,
                ],
                [
                    "6-666-5-443",
                    "5-443-6-666",
                    make_ts(2000),
                    make_ts(2900),
                    "Attack Z",
                    TrafficType.ATTACK,
                ],
                [
                    "5-443-6-666",
                    "6-666-5-443",
                    make_ts(3000),
                    make_ts(3900),
                    "",
                    TrafficType.BENIGN,
                ],
            ],
            columns=[
                COL_FLOW_ID,
                COL_REVERSE_FLOW_ID,
                COL_START_TIME,
                COL_END_TIME,
                COL_INFO,
                COL_TRAFFIC_TYPE,
            ],
        )
        self.attack_flows.set_index(COL_FLOW_ID, inplace=True)

    def test_find_attack_flows(self):
        global traffic_packets
        for use_end_time in [True, False]:
            associator = PacketLabelAssociatorTestImpl(
                self.attack_flows, traffic_packets, use_end_time=use_end_time
            )
            result, indexes = associator._find_attack_flows(self.attack_flows)
            expected_attack_flows = {
                "1-80-2-443",
                "2-443-1-80",
                "2-443-3-9000",
                "4-1111-2-443",
                "2-443-4-1111",
                "6-666-5-443",
            }
            assert set(result.index.values.tolist()) == expected_attack_flows
            assert indexes == expected_attack_flows
            associator.associate_pcap_labels("pcap")
            result_df = pandas.read_csv(
                associator.output_file.name, index_col="packet_id"
            )
            result_df = result_df.fillna(value=-1)
            for attack_name, packets in attack_packets.items():
                for packet in packets:
                    assert_traffic_type_attack(
                        result_df, packet, TrafficType.ATTACK, attack_name
                    )
            for packet in benign_packets:
                assert_traffic_type_attack(
                    result_df, packet, TrafficType.BENIGN, exp_attack_name=-1
                )
            self.assertEqual(len(associator.unmatched_packets["no_flow_ids"]), 1)
            self.assertEqual(
                associator.unmatched_packets["no_flow_ids"][0],
                (9999, f"pcap-{len(traffic_packets)-1}"),
            )
            self.assertEqual(
                associator.unmatched_packets["attack_without_flow"],
                [
                    (
                        100,
                        "pcap-0",
                        ("1-80-2-443", "2-443-1-80"),
                    ),
                    (200, "pcap-1", ("6-666-5-443", "5-443-6-666")),
                ],
            )


def assert_traffic_type_attack(df, packet, exp_traffic_type, exp_attack_name=None):
    packet_id = "pcap-%s" % traffic_packets.index(packet)
    act_tt = df.loc[packet_id]["traffic_type"]
    if act_tt != exp_traffic_type.value:
        raise AssertionError(
            "Expected %s (packet=%s) to have traffic type %s, but got %s"
            % (packet_id, packet, exp_traffic_type, act_tt)
        )
    act_at = df.loc[packet_id]["attack_type"]
    if act_at != exp_attack_name:
        raise AssertionError(
            "Expected %s (packet=%s) to have attack type %s, but got %s"
            % (packet_id, packet, exp_attack_name, act_at)
        )


if __name__ == "__main__":
    unittest.main()
