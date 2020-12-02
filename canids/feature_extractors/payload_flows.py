import argparse
import typing as t

import numpy as np

from canids.feature_extractors.basic_netflow_extractor import (
    BasicNetflowFeatureExtractor,
    NetFlow,
    FeatureSetMode,
)
from canids.types import TrafficSequence, Features, FeatureType


def yield_groups(iterator, max_group_length):
    current_parts = []
    for i, item in enumerate(iterator):
        if i > 0 and i % max_group_length == 0:
            yield current_parts
            current_parts = []
        current_parts.append(item)
    if len(current_parts) > 0:
        yield current_parts


class NetflowPayloadAnalyser(BasicNetflowFeatureExtractor):
    def __init__(
        self,
        **kwargs,
    ):
        super(NetflowPayloadAnalyser, self).__init__(**kwargs)

    def fit_extract(self, traffic: TrafficSequence) -> Features:
        flows = super(NetflowPayloadAnalyser, self)._make_flows(traffic)
        flow_features = super(NetflowPayloadAnalyser, self)._extract_flow_features(
            flows
        )
        payload_features = self._extract_payload_features(flows)
        return flow_features.combine(payload_features)

    def extract_features(self, traffic: TrafficSequence) -> Features:
        return self.fit_extract(traffic)

    def _extract_payload_features(self, flows: t.List[NetFlow]) -> Features:
        payload_features = []
        for flow in flows:
            counts = [0] * 256
            total_bytes = 0
            for ts, ip in flow.packets:
                for byte in bytes(ip.data):
                    counts[byte] += 1
                    total_bytes += 1
            distribution = [abs_freq / total_bytes for abs_freq in counts]
            payload_features.append(distribution)

        return Features(
            data=np.array(payload_features, ndmin=2),
            names=["freq_byte_%s" % i for i in range(256)],
            types=[FeatureType.FLOAT for _ in range(256)],
        )

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        BasicNetflowFeatureExtractor.init_parser(parser)

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return NetflowPayloadAnalyser(
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
            verbose=args.verbose,
            modes=[FeatureSetMode(v) for v in args.nf_mode],
        )

    def __str__(self):
        return self.get_id()

    def get_id(self) -> str:
        return (
            f"PayloadFlowAnalyser(base_extractor=%s)"
            % super(NetflowPayloadAnalyser, self).get_id()
        )

    @staticmethod
    def get_name() -> str:
        return "flows_payload"

    def get_db_params_dict(self):
        base = super(NetflowPayloadAnalyser, self).get_db_params_dict()
        base.update({})
        return base
