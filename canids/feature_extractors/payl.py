import argparse
import logging
import statistics
import typing as t

import dpkt
import numpy as np

from canids.feature_extractors.basic_netflow_extractor import (
    NetFlow,
    IPPacket,
    FeatureSetMode,
    Protocol,
)
from canids.feature_extractors.payload_flows import AbstractNetflowExtender
from canids.types import Features, FeatureType


class ByteDistributionInfo(t.NamedTuple):
    mean_byte_freq: np.array
    mean_squared_freq: np.array
    total_instances: int
    packet_length: int
    # storing the stddevs for each byte distribution here might not be optimal efficient as they are calculated
    # with each training update, even when not needed. However, the performance loss should only be marginal
    stddevs: np.array

    @staticmethod
    def init_with(
        byte_counts: t.List[int], packet_length: int
    ) -> "ByteDistributionInfo":
        byte_counts = np.array(byte_counts)
        byte_frequencies = byte_counts / packet_length
        return ByteDistributionInfo(
            mean_byte_freq=byte_frequencies,
            mean_squared_freq=np.square(byte_frequencies),
            total_instances=1,
            packet_length=packet_length,
            stddevs=np.array([0] * len(byte_counts)),
        )

    def update_with(self, new_byte_counts: t.List[int]) -> "ByteDistributionInfo":
        byte_frequencies = np.array(new_byte_counts) / self.packet_length
        mean_byte_freq = self.mean_byte_freq + (
            byte_frequencies - self.mean_byte_freq
        ) / (self.total_instances + 1)
        mean_squared_freq = self.mean_squared_freq + (
            np.square(byte_frequencies) - self.mean_squared_freq
        ) / (self.total_instances + 1)
        variances = mean_squared_freq - np.square(mean_byte_freq)
        return self._replace(
            mean_byte_freq=mean_byte_freq,
            mean_squared_freq=mean_squared_freq,
            total_instances=self.total_instances + 1,
            stddevs=np.sqrt(variances),
        )


Port = int
PacketLength = int
NO_MATCHING_DISTRIBUTION = -1
ByteDistributionId = t.Tuple[PacketLength, Port, Protocol]


class Distributions:
    def __init__(self):
        self.by_proto: t.Dict[Protocol, t.Dict[Port, t.Dict[PacketLength]]] = {}

    def get_by_id(
        self, distribution_id: ByteDistributionId
    ) -> t.Optional[ByteDistributionInfo]:
        packet_length, port, protocol = distribution_id
        if protocol not in self.by_proto:
            return None
        if port not in self.by_proto[protocol]:
            return None
        if packet_length not in self.by_proto[protocol][port]:
            return None
        return self.by_proto[protocol][port][packet_length]

    def add_distribution(
        self,
        distribution_id: ByteDistributionId,
        new_distribution: ByteDistributionInfo,
    ):
        packet_length, port, protocol = distribution_id
        if protocol not in self.by_proto:
            self.by_proto[protocol] = {}
        if port not in self.by_proto[protocol]:
            self.by_proto[protocol][port] = {}
        self.by_proto[protocol][port][packet_length] = new_distribution

    def update_distibution(
        self,
        distribution_id: ByteDistributionId,
        new_distribution: ByteDistributionInfo,
    ):
        packet_length, port, protocol = distribution_id
        self.by_proto[protocol][port][packet_length] = new_distribution

    def get_nearest(self, distribution_id: ByteDistributionId):
        packet_length, port, protocol = distribution_id
        if protocol not in self.by_proto:
            return None
        if port not in self.by_proto[protocol]:
            return None
        distributions = self.by_proto[protocol][port]
        if packet_length in distributions:
            return distributions[packet_length]
        nearest_length = self._get_nearest_packet_length(
            packet_length, list(distributions.keys())
        )
        return distributions[nearest_length]

    def _get_nearest_packet_length(
        self, packet_length: int, all_packet_lengths: t.List[int]
    ):
        # this could be accelerated by storing an ordered list of all packet lengths in memory
        # (for each (port, proto) combination)
        min_index, _ = min(
            enumerate(all_packet_lengths), key=lambda item: abs(item[1] - packet_length)
        )
        return all_packet_lengths[min_index]


class PaylModel:
    def __init__(self, smoothing: int):
        self.smoothing = smoothing
        self.distributions = Distributions()

    def train(self, flows: t.List[NetFlow]):
        for flow in flows:
            for _, ip in flow.packets:
                self._train_packet(flow.dest_port, ip)

    def _train_packet(self, port: Port, ip: dpkt.ip.IP):
        counts = self._count_bytes(ip)
        packet_length = len(ip.data)
        distribution_id = (packet_length, port, ip.p)
        distr = self.distributions.get_by_id(distribution_id)
        if distr is None:
            new_distribution = ByteDistributionInfo.init_with(
                byte_counts=counts, packet_length=packet_length
            )
            self.distributions.add_distribution(distribution_id, new_distribution)
        else:
            new_distr = distr.update_with(counts)
            self.distributions.update_distibution(distribution_id, new_distr)

    def _count_bytes(self, ip_packet: dpkt.ip.IP):
        counts = [0] * 256
        for byte in bytes(ip_packet.data):
            counts[byte] = counts[byte] + 1
        return counts

    def calc_abs(self, port: Port, packet: IPPacket) -> float:
        _, ip = packet
        packet_length = len(ip.data)
        distribution_id = (packet_length, port, ip.p)
        distribution = self.distributions.get_nearest(distribution_id)
        if distribution is None:
            logging.info("No matching distribution found for %s", distribution_id)
            return NO_MATCHING_DISTRIBUTION
        counts = np.array(self._count_bytes(ip))
        byte_freq = counts / packet_length
        # noinspection PyTypeChecker
        distance: float = np.sum(
            np.abs(distribution.mean_byte_freq, byte_freq)
            / (distribution.stddevs + self.smoothing)
        )
        return distance


class PaylExtractor(AbstractNetflowExtender):
    def __init__(self, smoothing, *args, **kwargs):
        super(PaylExtractor, self).__init__(**kwargs)
        self.payl = PaylModel(smoothing)

    def _fit_extract_additional_features(self, flows: t.List[NetFlow]) -> Features:
        self.payl.train(flows)
        return self._extract_additional_features(flows)

    def _extract_additional_features(self, flows: t.List[NetFlow]) -> Features:
        features = [self._make_flow_features(flow) for flow in flows]
        return Features(
            data=np.array(features),
            names=["mean_payl_dist", "min_payl_dist", "max_payl_dist", "std_payl"],
            types=[
                FeatureType.FLOAT,
                FeatureType.FLOAT,
                FeatureType.FLOAT,
                FeatureType.FLOAT,
            ],
        )

    def _make_flow_features(self, flow: NetFlow):
        mahalanobis = [
            self.payl.calc_abs(flow.dest_port, packet) for packet in flow.packets
        ]
        return [
            statistics.mean(mahalanobis),
            min(mahalanobis),
            max(mahalanobis),
            statistics.pstdev(mahalanobis),
        ]

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        AbstractNetflowExtender.init_parser(parser)
        parser.add_argument(
            "--smoothing",
            type=float,
            default=0.0001,
            help="Smoothing value for the mahalanobis distance calculation",
        )

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return PaylExtractor(
            smoothing=args.smoothing,
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
            verbose=args.verbose,
            modes=[FeatureSetMode(v) for v in args.nf_mode],
        )

    @staticmethod
    def get_name() -> str:
        return "payl_flows"

    def _get_additional_db_params(self):
        return {"smoothing": self.payl.smoothing}

    def _get_additional_id_info(self):
        return "(smoothing=%s)" % self.payl.smoothing
