import typing as t
from datetime import datetime

import pyshark

from anomaly_detection.types import DatasetPreprocessor
from dataset_utils.cic_ids_2017 import *

FILES = {
    "PCAPs/Wednesday-WorkingHours.pcap": "labels/Wednesday-workingHours.pcap_ISCX.csv",
    "PCAPs/Monday-WorkingHours.pcap": "labels/Monday-WorkingHours.pcap_ISCX.csv"
}  # TODO add all

PacketID = str


def make_flow_ids(pkg: Packet):
    if "ip" not in pkg:
        logging.warning("no ip packet")
        return None
    src_ip = str(pkg.ip.addr)
    dest_ip = str(pkg.ip.dst)
    if "tcp" in pkg:
        src_port = int(pkg.tcp.port)
        dest_port = int(pkg.tcp.dstport)
        protocol = 6
    elif "udp" in pkg:
        src_port = int(pkg.udp.port)
        dest_port = int(pkg.udp.dstport)
        protocol = 17
    else:
        src_port = 0
        dest_port = 0
        protocol = 0
    return [format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol),
            format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=False)]


def format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=False):
    if not reverse:
        return "%s-%s-%s-%s-%s" % (src_ip, dest_ip, src_port, dest_port, protocol)
    return "%s-%s-%s-%s-%s" % (dest_ip, src_ip, dest_port, src_port, protocol)


def get_packet_id(pkg: Packet, flow_ids: t.List[str] = None) -> PacketID:
    if flow_ids is None:
        flow_ids = make_flow_ids(pkg)
    if flow_ids is None:
        return "<no-ip>" + pkg.sniff_timestamp
    else:
        return flow_ids[0] + pkg.sniff_timestamp


def determine_traffic_type(matching_labels: pandas.DataFrame):
    if len(matching_labels) == 1:
        return label_to_traffic_type(matching_labels["Label"].values[0])

    labels = set(matching_labels["Label"].values)
    if len(labels) > 1:
        # TODO compare for timestamp
        logging.warning("TODO compare for time")
        return TrafficType.UNKNOWN
    else:
        return label_to_traffic_type(labels.pop())


class CICIDS2017Preprocessor(DatasetPreprocessor):

    def preprocess(self, dataset_path: str):
        print(dataset_path)
        for pcap_file, label_file in self.pcap_and_label_files(dataset_path):
            attacks_packet_ids = self.get_attacks_packet_ids(label_file)
            labels = self.generate_labels(pcap_file, attacks_packet_ids)
            pandas_dict = {packet_id: [packet_id, label] for packet_id, label in labels.items()}
            df = pandas.DataFrame.from_dict(pandas_dict, orient="index", columns=["packet_id", "label"])
            output_csv_path = os.path.join(dataset_path, os.path.basename(pcap_file) + "_packet_labels.csv")
            df.to_csv(output_csv_path, index=False)

    def generate_labels(self, pcap_file: str, attack_times: pandas.DataFrame) \
            -> t.Dict[PacketID, TrafficType]:
        packets = pyshark.FileCapture(pcap_file, keep_packets=False)
        labelled_packets: t.Dict[PacketID, TrafficType] = dict()
        progress = 0
        for packet in packets:
            flow_ids = make_flow_ids(packet)
            packet_id = get_packet_id(packet, flow_ids)
            if (flow_ids is None) or \
                    not (flow_ids[0] in attack_times.index or flow_ids[1] in attack_times.index):
                labelled_packets[packet_id] = TrafficType.BENIGN.value
            else:
                # check for attack times
                labelled_packets[packet_id] = TrafficType.ATTACK.value
            if progress % 1000 == 0:
                print(progress)
            progress += 1
        return labelled_packets

    def get_attacks_packet_ids(self, flows_file: str) -> pandas.DataFrame:
        df = read_csv(flows_file)  # TODO
        attacks = df.loc[df["Label"] != BENIGN_LABEL]
        benigns = df.loc[df["Label"] == BENIGN_LABEL]
        attacks["reverse_flow_id"] = attacks.index.map(lambda flow: self.reverse_flow_id(flow))
        in_both = pandas.merge(attacks, benigns, how="inner", left_index=True, right_index=True)
        in_both_reversed_id = pandas.merge(attacks, benigns, how="inner", left_on="reverse_flow_id", right_index=True)
        in_both = pandas.concat([in_both, in_both_reversed_id])
        benign_times = in_both["Timestamp_y"].groupby(in_both.index).apply(
            lambda elements: [self.date_to_timestamp(formatted_date) for formatted_date in list(elements)]
        )
        attack_times = attacks["Timestamp"].groupby(attacks.index).apply(
            lambda elements: [self.date_to_timestamp(formatted_date) for formatted_date in list(elements)]
        )
        result_df = pandas.merge(attack_times, benign_times, how="left", right_index=True, left_index=True)
        result_df.rename(columns={"Timestamp_y": "benign", "Timestamp": "attack"}, inplace=True)
        return result_df

    def pcap_and_label_files(self, dataset_path: str) -> t.List[t.Tuple[str, str]]:
        return [(os.path.join(dataset_path, pcap), os.path.join(dataset_path, label_file)) \
                for pcap, label_file in FILES.items()]

    @staticmethod
    def reverse_flow_id(flow_id: str):
        splitted = flow_id.split("-")
        if len(splitted) != 5:
            return "<invalid flow>"
        src_ip, dest_ip, src_port, dest_port, protocol = splitted
        return format_flow_id(src_ip, dest_ip, src_port, dest_port, protocol, reverse=True)

    def date_to_timestamp(self, datestr: str):
        date_part, time_part = datestr.split(" ")
        d, m, y = date_part.split("/")
        if len(d) != 2:
            d = "0" + d
        if len(m) != 2:
            m = "0" + m
        date_part = f"{d}/{m}/{y}"
        if time_part[1] == ":":
            time_part = "0" + time_part
        datestr = f"{date_part} {time_part}"
        result = datetime.strptime(datestr, "%d/%m/%Y %I:%M")  # example "5/7/2017 8:42" = 5th of July 2017
        return result