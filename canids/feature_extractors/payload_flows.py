import argparse
import typing as t
from abc import abstractmethod, ABC

import numpy as np

from canids.feature_extractors.basic_netflow_extractor import (
    BasicNetflowFeatureExtractor,
    NetFlow,
    FeatureSetMode,
)
from canids.types import TrafficSequence, Features, FeatureType


class AbstractNetflowExtender(BasicNetflowFeatureExtractor, ABC):
    def __init__(
        self,
        **kwargs,
    ):
        super(AbstractNetflowExtender, self).__init__(**kwargs)

    def fit_extract(self, traffic: TrafficSequence) -> Features:
        return self._extract_flows_and_combine(
            traffic, self._fit_extract_additional_features
        )

    def extract_features(self, traffic: TrafficSequence) -> Features:
        return self._extract_flows_and_combine(
            traffic, self._extract_additional_features
        )

    def _extract_flows_and_combine(self, traffic: TrafficSequence, additional_feat_gen):
        flows = super(AbstractNetflowExtender, self)._make_flows(traffic)
        flow_features = super(AbstractNetflowExtender, self)._extract_flow_features(
            flows
        )
        additional_features = additional_feat_gen(flows)
        return flow_features.combine(additional_features)

    @abstractmethod
    def _extract_additional_features(self, flows: t.List[NetFlow]) -> Features:
        raise NotImplementedError()

    def _fit_extract_additional_features(self, flows: t.List[NetFlow]) -> Features:
        return self._extract_additional_features(flows)

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        BasicNetflowFeatureExtractor.init_parser(parser)

    def __str__(self):
        return self.get_id()

    def get_id(self) -> str:
        additional_subclass_info = self._get_additional_id_info()
        return f"%s(base_extractor=%s, info=%s)" % (
            self.__class__.__name__,
            super(AbstractNetflowExtender, self).get_id(),
            additional_subclass_info,
        )

    def _get_additional_id_info(self):
        return "{}"

    def get_db_params_dict(self):
        base = super(AbstractNetflowExtender, self).get_db_params_dict()
        base.update(self._get_additional_db_params())
        return base

    def _get_additional_db_params(self):
        return {}


class NetflowPayloadAnalyser(AbstractNetflowExtender):
    def __init__(
        self,
        **kwargs,
    ):
        super(NetflowPayloadAnalyser, self).__init__(**kwargs)

    def _extract_additional_features(self, flows: t.List[NetFlow]) -> Features:
        payload_features = []
        for flow in flows:
            counts = [0] * 256
            total_bytes = 0
            for _, ip in flow.packets:
                for byte in bytes(ip.data):
                    counts[byte] = counts[byte] + 1
                    total_bytes += 1
            distribution = [abs_freq / total_bytes for abs_freq in counts]
            payload_features.append(distribution)

        return Features(
            data=np.array(payload_features, ndmin=2),
            names=["freq_byte_%s" % i for i in range(256)],
            types=[FeatureType.FLOAT for _ in range(256)],
        )

    def init_by_parsed(args: argparse.Namespace):
        return NetflowPayloadAnalyser(
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
            hindsight_window=args.hindsight_window,
            verbose=args.verbose,
            modes=[FeatureSetMode(v) for v in args.nf_mode],
        )

    @staticmethod
    def get_name() -> str:
        return "flows_payload"
