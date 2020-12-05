import argparse
import os
import typing as t

from canids.dataset_utils.cic_ids_2017 import CICIDS2017
from canids.dataset_utils.unsw_nb15 import UNSWNB15
from canids.decision_engines.autoencoder import AutoencoderDE
from canids.decision_engines.one_class_svm import OneClassSVMDE
from canids.feature_extractors.basic_netflow_extractor import (
    BasicNetflowFeatureExtractor,
)
from canids.feature_extractors.payl import PaylExtractor
from canids.feature_extractors.payload_flows import (
    NetflowPayloadAnalyser,
)
from canids.feature_extractors.testing_extractor import (
    DummyDataset,
)
from canids.transformers import (
    StandardScalerTransformer,
    OneHotEncoder,
    MinMaxScalerTransformer,
)
from canids.types import FeatureExtractor, DecisionEngine, ParsingException


def create_fe_and_de(
    fe_name: str, de_name: str, args: t.Sequence[str]
) -> t.Tuple[FeatureExtractor, DecisionEngine, str, t.List[argparse.ArgumentParser]]:
    if fe_name not in FEATURE_EXTRACTORS:
        raise ParsingException(
            f"{fe_name} is not a valid feature extractor. Please specify one of: {FEATURE_EXTRACTORS.keys()}"
        )
    feature_extractor_class = FEATURE_EXTRACTORS[fe_name]
    fe_parser = argparse.ArgumentParser(prog=f"Feature Extractor ({fe_name})")
    feature_extractor_class.init_parser(fe_parser)
    parsed, unknown = fe_parser.parse_known_args(args)
    feature_extractor = feature_extractor_class.init_by_parsed(parsed)

    if de_name not in DECISION_ENGINES:
        raise ParsingException(
            f"{de_name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES.keys()}"
        )
    de_class, de_create_parser = DECISION_ENGINES[de_name]
    de_parser = de_create_parser(prog_name=f"Decision Engine ({de_name})")
    parsed, unknown = de_parser.parse_known_args(unknown)
    decision_engine_instance = de_class(parsed_args=parsed)
    return feature_extractor, decision_engine_instance, unknown, [fe_parser, de_parser]


def build_transformers(names: t.Sequence[str]):
    transformers = list()
    for name in names:
        if name not in TRANSFORMERS:
            raise ParsingException(
                f"{name} is not a valid transformer. Please specify one of: {TRANSFORMERS.keys()}"
            )
        transformers.append(TRANSFORMERS[name]())
    return transformers


DATASET_PATH = os.path.join(os.path.dirname(__file__), "data/cic-ids-2017/")
DECISION_ENGINES = {
    de.get_name(): (de, de.create_parser)
    for de in [
        AutoencoderDE,
        #   LocalOutlierFactorDE,
        OneClassSVMDE,
    ]
}
TRANSFORMERS = {
    "minmax_scaler": MinMaxScalerTransformer,
    "standard_scaler": StandardScalerTransformer,
    "onehot_encoder": OneHotEncoder,
}
FEATURE_EXTRACTORS = {
    fe.get_name(): fe
    for fe in [BasicNetflowFeatureExtractor, NetflowPayloadAnalyser, PaylExtractor]
}

DATASET_UTILS = {
    "cic-ids-2017": CICIDS2017,
    "unsw-nb15": UNSWNB15,
    "test": DummyDataset,
}
