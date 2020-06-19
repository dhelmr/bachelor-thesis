import socket
import typing as t
from datetime import datetime

import dpkt as dpkt

from anomaly_detection.types import DatasetPreprocessor
from dataset_utils import pcap_utils
from dataset_utils.cic_ids_2017 import *

FILES = {
    "PCAPs/Wednesday-WorkingHours.pcap": "labels/Wednesday-workingHours.pcap_ISCX.csv",
    "PCAPs/Monday-WorkingHours.pcap": "labels/Monday-WorkingHours.pcap_ISCX.csv"
}  # TODO add all

PacketID = str


def make_flow_ids(ts, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    if type(eth.data) is not dpkt.ip.IP:
        return None
    src_ip = socket.inet_ntoa(eth.ip.src)
    dest_ip = socket.inet_ntoa(eth.ip.dst)
    if type(eth.ip.data) is dpkt.tcp.TCP:
        src_port = int(eth.ip.tcp.sport)
        dest_port = int(eth.ip.tcp.dport)
        protocol = 6
    elif type(eth.ip.data) is dpkt.udp.UDP:
        src_port = int(eth.ip.udp.sport)
        dest_port = int(eth.ip.udp.dport)
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


def get_packet_id(timestamp, buf, flow_ids: t.List[str] = None) -> PacketID:
    if flow_ids is None:
        flow_ids = make_flow_ids(timestamp, buf)
    if flow_ids is None:
        return "<no-ip>-%s" % timestamp
    else:
        return "%s-%s" % (flow_ids[0], timestamp)


class CICIDS2017Preprocessor(DatasetPreprocessor):

    def preprocess(self, dataset_path: str):
        for pcap_file, label_file in self.pcap_and_label_files(dataset_path):
            logging.info("Process file %s", pcap_file)
            attacks_packet_ids = self.get_attacks_packet_ids(label_file)
            labels = self.generate_labels(pcap_file, attacks_packet_ids)
            df = pandas.DataFrame.from_records(labels, columns=["packet_id", "label"])
            output_csv_path = os.path.join(dataset_path, os.path.basename(pcap_file) + "_packet_labels.csv")
            logging.info("Write packet labels into %s", label_file)
            df.to_csv(output_csv_path, index=False)

    def generate_labels(self, pcap_file: str, attack_times: pandas.DataFrame) \
            -> t.List[t.Tuple[PacketID, TrafficType]]:
        packets = pcap_utils.read_pcap_pcapng(pcap_file)
        labelled_packets: t.List[t.Tuple[PacketID, TrafficType]] = list()
        progress = 0
        for timestamp, buf in packets:
            flow_ids = make_flow_ids(timestamp, buf)
            packet_id = get_packet_id(timestamp, buf, flow_ids)
            if (flow_ids is None) or \
                    not (flow_ids[0] in attack_times.index or flow_ids[1] in attack_times.index):
                traffic_type = TrafficType.BENIGN
            else:
                # check for attack times
                traffic_type = TrafficType.ATTACK
            entry = (packet_id, traffic_type.value)
            labelled_packets.append(entry)
            if progress % 50000 == 0:
                logging.info("Processed %s packets...", progress)
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
