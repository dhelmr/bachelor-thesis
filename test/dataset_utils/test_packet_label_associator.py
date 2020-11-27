import datetime
import itertools
import tempfile
import unittest
from typing import List

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
    COL_SRC_IP,
    COL_DEST_PKTS,
    COL_SRC_PKTS,
    COL_SRC_PORT,
    FlowProperties,
    FlowIdentification,
    SrcIdentification,
)
from canids.types import TrafficType, Packet


class PacketLabelAssociatorTestImpl(PacketLabelAssociator):
    def __init__(self, flows, packets, *args, **kwargs):
        super().__init__(additional_cols=["attack_type"], *args, **kwargs)
        self.output_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.flows = flows
        self.packets = packets

    def make_flow_ids(self, packet: Packet) -> FlowIdentification:
        ts, buf = packet
        flow_id = str(buf)
        splitted = flow_id.split("-")
        if len(splitted) != 4:
            return None
        reverse_id = "-".join([splitted[2], splitted[3], splitted[0], splitted[1]])
        return FlowIdentification(
            flow_id,
            reverse_id,
            uni_from_src=SrcIdentification(
                ip_address=splitted[0], port=int(splitted[1])
            ),
        )

    def output_csv_file(self, pcap_file) -> str:
        return self.output_file.name

    def _date_cell_to_timestamp(self, cell_content) -> datetime.datetime:
        return cell_content

    def _unpack_additional_info(self, additional_info: AdditionalInfo) -> List[str]:
        return [additional_info if additional_info is not None else ""]

    def _open_pcap(self, pcap_file):
        return self.packets

    def _get_flows_for_pcap(self, pcap_file):
        return self._find_attack_flows(self.flows)


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
    "Attack Uni": [(2000, "4-333-5-333"), (2100, "4-333-5-333")],
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
# the following packet must be classified as attack "Attack-Uni", if recognize_uni_flows=False and classified
# as benign else
special_unidirectional_packet = (99900, "5-333-4-333")
traffic_packets = list(
    sorted(
        list(itertools.chain(*attack_packets.values()))
        + benign_packets
        + [special_unidirectional_packet],
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
                    "1",
                    88,
                    4,
                    33,
                ],
                [
                    "1-80-2-443",
                    "2-443-1-80",
                    make_ts(2000),
                    make_ts(2900),
                    "",
                    TrafficType.BENIGN,
                    "1",
                    88,
                    20,
                    4,
                ],
                [
                    "2-443-1-80",
                    "1-80-2-443",
                    make_ts(4000),
                    make_ts(5100),
                    "Attack B",
                    TrafficType.ATTACK,
                    "2",
                    443,
                    20,
                    4,
                ],
                [
                    "2-443-3-9000",
                    "3-9000-2-443",
                    make_ts(1000),
                    make_ts(3800),
                    "Attack A",
                    TrafficType.ATTACK,
                    "2",
                    443,
                    20,
                    4,
                ],
                [
                    "3-9000-2-443",
                    "2-433-3-9000",
                    make_ts(4000),
                    make_ts(4900),
                    "",
                    TrafficType.BENIGN,
                    "3",
                    9000,
                    4,
                    4,
                ],
                [
                    "2-443-3-9000",
                    "3-9000-2-443",
                    make_ts(6000),
                    make_ts(6950),
                    "Attack B",
                    TrafficType.ATTACK,
                    "2",
                    443,
                    44,
                    222,
                ],
                [
                    "4-1111-2-443",
                    "2-443-4-1111",
                    make_ts(1000),
                    make_ts(1500),
                    "Attack C",
                    TrafficType.ATTACK,
                    "4",
                    1111,
                    3,
                    2,
                ],
                [
                    "2-443-4-1111",
                    "4-1111-2-443",
                    make_ts(3000),
                    make_ts(3002),
                    "Attack E",
                    TrafficType.ATTACK,
                    "2",
                    443,
                    22,
                    33,
                ],
                [
                    "4-1111-2-443",
                    "2-443-4-1111",
                    make_ts(5000),
                    make_ts(6000),
                    "",
                    TrafficType.BENIGN,
                    "4",
                    1111,
                    222,
                    3,
                ],
                [
                    "2-443-1-80",
                    "1-80-2-443",
                    make_ts(3000),
                    make_ts(3100),
                    "Attack C",
                    TrafficType.ATTACK,
                    "2",
                    443,
                    44,
                    22,
                ],
                [
                    "5-5151-2-443",
                    "2-443-5-5151",
                    make_ts(1000),
                    make_ts(2900),
                    "",
                    TrafficType.BENIGN,
                    "5",
                    5151,
                    2,
                    2,
                ],
                [
                    "6-666-5-443",
                    "5-443-6-666",
                    make_ts(2000),
                    make_ts(2900),
                    "Attack Z",
                    TrafficType.ATTACK,
                    "6",
                    666,
                    44,
                    44,
                ],
                [
                    "5-443-6-666",
                    "6-666-5-443",
                    make_ts(3000),
                    make_ts(3900),
                    "",
                    TrafficType.BENIGN,
                    "5",
                    443,
                    3,
                    2,
                ],
                [  # unidirectional flow
                    "4-333-5-333",
                    "5-333-4-333",
                    make_ts(2000),
                    make_ts(100_000),
                    "Attack Uni",
                    TrafficType.ATTACK,
                    "4",
                    333,
                    2,
                    0,
                ],
            ],
            columns=[
                COL_FLOW_ID,
                COL_REVERSE_FLOW_ID,
                COL_START_TIME,
                COL_END_TIME,
                COL_INFO,
                COL_TRAFFIC_TYPE,
                COL_SRC_IP,
                COL_SRC_PORT,
                COL_SRC_PKTS,
                COL_DEST_PKTS,
            ],
        )
        self.attack_flows.set_index(COL_FLOW_ID, inplace=True)

    def test_find_attack_flows(self):
        global traffic_packets

        def iter_configurations():
            for use_end_time in [True, False]:
                for recognize_uni_flows in [True, False]:
                    yield use_end_time, recognize_uni_flows

        for use_end_time, recognize_uni_flows in iter_configurations():
            associator = PacketLabelAssociatorTestImpl(
                self.attack_flows,
                traffic_packets,
                use_end_time=use_end_time,
                recognize_uni_flows=recognize_uni_flows,
            )
            result, indexes = associator._find_attack_flows(self.attack_flows)
            expected_attack_flows = {
                "1-80-2-443",
                "2-443-1-80",
                "2-443-3-9000",
                "4-1111-2-443",
                "2-443-4-1111",
                "6-666-5-443",
                "4-333-5-333",
            }
            assert set(result.index.values.tolist()) == expected_attack_flows
            assert indexes == expected_attack_flows
            associator.associate_pcap_labels("pcap")
            result_df = pandas.read_csv(
                associator.output_file.name, index_col="packet_id"
            )
            result_df = result_df.fillna(value=-1)
            for attack_name, packets in attack_packets.items():
                if not recognize_uni_flows and attack_name == "Attack Uni":
                    packets = packets + [special_unidirectional_packet]
                for packet in packets:
                    assert_traffic_type_attack(
                        result_df, packet, TrafficType.ATTACK, attack_name
                    )
            for packet in benign_packets:
                assert_traffic_type_attack(
                    result_df, packet, TrafficType.BENIGN, exp_attack_name=-1
                )
            self.assertEqual(len(associator.report.no_flow_ids), 1)
            self.assertEqual(
                associator.report.no_flow_ids[0],
                (9999, f"pcap-{len(traffic_packets) - 2}"),
            )

            expected_no_flow_packets = [
                (
                    100,
                    "pcap-0",
                    ["1-80-2-443", "2-443-1-80"],
                ),
                (200, "pcap-1", ["6-666-5-443", "5-443-6-666"]),
            ]
            if recognize_uni_flows:
                expected_no_flow_packets += [
                    (
                        99900,
                        f"pcap-{len(traffic_packets) - 1}",
                        ["5-333-4-333", "4-333-5-333"],
                    )
                ]
            self.assertEqual(
                associator.report.attack_without_flow,
                expected_no_flow_packets,
                msg=f"Not equal for use_end_time={use_end_time} and recognize_uni_flows={recognize_uni_flows}",
            )

    def test_match_packets(self):
        potential_flows = [
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(2300),
                end_time=make_ts(4000),
                traffic_type=TrafficType.ATTACK,
                additional_info="A",
            ),
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(4001),
                end_time=make_ts(4100),
                traffic_type=TrafficType.BENIGN,
                additional_info="B",
            ),
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(7000),
                end_time=make_ts(8100),
                traffic_type=TrafficType.ATTACK,
                additional_info="C",
            ),
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(9300),
                end_time=make_ts(9900),
                traffic_type=TrafficType.ATTACK,
                additional_info="D",
            ),
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(10010),
                end_time=make_ts(20000),
                traffic_type=TrafficType.BENIGN,
                additional_info="E",
            ),
            FlowProperties(
                ids=FlowIdentification("", ""),
                start_time=make_ts(23000),
                end_time=make_ts(30000),
                traffic_type=TrafficType.ATTACK,
                additional_info="F",
            ),
        ]

        with_end_time = PacketLabelAssociatorTestImpl(None, None, use_end_time=True)
        expected_flow_info_with_endtime = {
            40: None,  # timestamp 40 is not in any flow
            2300: "A",  # timestamp 2300 is in flow with info "A"
            2301: "A",
            3999: "A",
            4000: "A",
            4001: "B",
            4100: "B",
            4101: None,  # not in any flow, when end_time is considered
            7000: "C",
            8000: "C",
            9300: "D",
            9900: "D",
            10000: None,
            10500: "E",
            23000: "F",
            23001: "F",
            27000: "F",
            30000: "F",
            30001: None,
            40000: None,
        }
        assert_matched_flows(
            self, with_end_time, expected_flow_info_with_endtime, potential_flows
        )

        without_end_time = PacketLabelAssociatorTestImpl(None, None, use_end_time=False)
        expected_flow_info_wo_endtime = {
            40: None,  # timestamp 40 is not in any flow
            2299: None,
            2300: "A",  # timestamp 2300 is in flow with info "A"
            2301: "A",
            3999: "A",
            4000: "A",
            4001: "B",
            4100: "B",
            4101: "B",  # now in Flow "B", because endtime is not considered
            7000: "C",
            8000: "C",
            9300: "D",
            9900: "D",
            10000: "D",
            10500: "E",
            23000: "F",
            23001: "F",
            27000: "F",
            30000: "F",
            30001: "F",
            40000: "F",
        }
        assert_matched_flows(
            self, without_end_time, expected_flow_info_wo_endtime, potential_flows
        )


def assert_matched_flows(
    test_instance,
    associator: PacketLabelAssociator,
    expected_flow_info,
    potential_flows,
):
    for ts, expected_info in expected_flow_info.items():
        matched_flow = associator._match_flow(make_ts(ts), potential_flows)
        actual_info = None if matched_flow is None else matched_flow.additional_info
        test_instance.assertEqual(
            actual_info,
            expected_info,
            msg="Matched wrong flow for timestamp %s (use_end_time=%s)" % (ts, "True"),
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
