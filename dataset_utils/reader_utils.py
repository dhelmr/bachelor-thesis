import datetime
import logging
import math

import pandas

from anomaly_detection.types import TrafficType


def packet_is_attack(flow_ids, timestamp: float, attack_times: pandas.DataFrame) -> TrafficType:
    potential_attack_flows = attack_times.loc[attack_times.index.isin(flow_ids)]
    attacks = potential_attack_flows["attack"].values[0]
    benigns = potential_attack_flows["benign"].values[0]
    if type(benigns) is float and math.isnan(benigns):
        return TrafficType.ATTACK
    elif type(attacks) is float and math.isnan(attacks):
        return TrafficType.BENIGN

    timestamp = datetime.datetime.utcfromtimestamp(timestamp)
    packet_type = get_traffic_type(timestamp, attacks, benigns)
    if packet_type is None:
        logging.error("Could not associate packet %s", flow_ids[0])
        packet_type = TrafficType.BENIGN
    return packet_type


def ranges_of_list(input_list, ranges):
    output_list = []
    for start, end in ranges:
        if end == "end":
            output_list += input_list[start:]
        else:
            output_list += input_list[start:end]
    return output_list


def get_traffic_type(ts, attack_times, benign_times):
    last_type = None
    while len(attack_times) != 0 or len(benign_times) != 0:
        if len(benign_times) == 0:
            if ts < attack_times[0]:
                return last_type
            else:
                return TrafficType.ATTACK
        if len(attack_times) == 0:
            if ts < benign_times[0]:
                return last_type
            else:
                return TrafficType.BENIGN
        if attack_times[0] < benign_times[0]:
            time = attack_times.pop(0)
            if ts < time:
                return last_type
            last_type = TrafficType.ATTACK
        else:
            time = benign_times.pop(0)
            if ts < time:
                return last_type
            last_type = TrafficType.BENIGN
    return last_type
