import argparse
import os
import typing as t

from anomaly_detection.decision_engines import local_outlier_factor as local_outlier_factor, \
    one_class_svm as one_class_svm, autoencoder
from anomaly_detection.decision_engines.autoencoder import AutoencoderDE
from anomaly_detection.feature_extractors.basic_netflow_extractor import BasicNetflowFeatureExtractor
from anomaly_detection.feature_extractors.basic_packet_feature_extractor import BasicPacketFeatureExtractor
from anomaly_detection.feature_extractors.doc2vec_packets import PacketDoc2Vec
from anomaly_detection.feature_extractors.netflow_doc2vec import NetflowDoc2Vec
from anomaly_detection.feature_extractors.testing_extractor import TestingFeatureExtractor, DummyTrafficGenerator, \
    DummyPreprocessor
from anomaly_detection.transformers import MinxMaxScalerTransformer, StandardScalerTransformer
from anomaly_detection.types import DatasetUtils
from anomaly_detection.types import FeatureExtractor, DecisionEngine, ParsingException
from dataset_utils import cic_ids_2017 as cic2017
from dataset_utils.cic_ids_2017 import CICIDS2017Preprocessor


def create_fe_and_de(fe_name: str,
                     de_name: str, args: t.Sequence[str]) \
        -> t.Tuple[FeatureExtractor, DecisionEngine, str, t.List[argparse.ArgumentParser]]:
    if fe_name not in FEATURE_EXTRACTORS:
        raise ParsingException(
            f"{fe_name} is not a valid feature extractor. Please specify one of: {FEATURE_EXTRACTORS.keys()}")
    feature_extractor_class = FEATURE_EXTRACTORS[fe_name]
    fe_parser = argparse.ArgumentParser(prog=f"Feature Extractor ({fe_name})")
    feature_extractor_class.init_parser(fe_parser)
    parsed, unknown = fe_parser.parse_known_args(args)
    feature_extractor = feature_extractor_class.init_by_parsed(parsed)

    if de_name not in DECISION_ENGINES:
        raise ParsingException(
            f"{de_name} is not a valid decision engine. Please specify one of: {DECISION_ENGINES.keys()}")
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
                f"{name} is not a valid transformer. Please specify one of: {TRANSFORMERS.keys()}")
        transformers.append(TRANSFORMERS[name]())
    return transformers


DATASET_PATH = os.path.join(os.path.dirname(
    __file__), "data/cic-ids-2017/")
DECISION_ENGINES = {
    "one_class_svm": (one_class_svm.OneClassSVMDE, one_class_svm.create_parser),
    "local_outlier_factor": (local_outlier_factor.LocalOutlierFactorDE, local_outlier_factor.create_parser),
    "autoencoder": (AutoencoderDE, autoencoder.create_parser)
}
TRANSFORMERS = {
    "minmax_scaler": MinxMaxScalerTransformer,
    "standard_scaler": StandardScalerTransformer
}
FEATURE_EXTRACTORS = {
    "basic_netflow": BasicNetflowFeatureExtractor,
    "basic_packet_info": BasicPacketFeatureExtractor,
    "doc2vec_packet": PacketDoc2Vec,
    "doc2vec_flows": NetflowDoc2Vec,
    "test": TestingFeatureExtractor
}
DATASET_UTILS = {
    "cic-ids-2017": DatasetUtils(cic2017.CIC2017TrafficReader, CICIDS2017Preprocessor),
    "test": DatasetUtils(DummyTrafficGenerator, DummyPreprocessor)
}
