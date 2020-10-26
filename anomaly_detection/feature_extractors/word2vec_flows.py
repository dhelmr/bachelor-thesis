import argparse
import itertools
import logging
import typing as t
from enum import Enum

import numpy as np
from gensim.models import Word2Vec
from gensim.models.doc2vec import TaggedDocument
from tqdm import tqdm

from anomaly_detection.feature_extractors.basic_netflow_extractor import BasicNetflowFeatureExtractor, NetFlow, \
    FeatureSetMode
from anomaly_detection.types import TrafficSequence, Features, FeatureType
from dataset_utils.pcap_utils import get_ip_packet


class TrainingMethod(Enum):
    SKIP_GRAM = "skip_gram"
    CBOW = "cbow"


def yield_groups(iterator, max_group_length):
    current_parts = []
    for i, item in enumerate(iterator):
        if i > 0 and i % max_group_length == 0:
            yield current_parts
            current_parts = []
        current_parts.append(item)
    if len(current_parts) > 0:
        yield current_parts


class NetflowPayloadSentenceGen:
    def __init__(self, flows: t.List[NetFlow], group_n_bytes):
        self.flows = flows
        self.group_n_bytes = group_n_bytes

    def __iter__(self) -> t.Iterable[TaggedDocument]:
        for i in range(len(self.flows)):
            flow = self.flows[i]
            flow_words = []
            for packet_i, packet in enumerate(flow.packets):
                _, buffer = packet
                ip = get_ip_packet(buffer)
                try:
                    data = bytes(ip.data.data)
                except Exception as e:
                    logging.error("Could not parse packet data for packet #%s of flow #%s: %s", packet_i, i, e)
                    data = bytes()
                # group n bytes to a word and transform into a string representation, for example "212.231.111.01" for a 4-byte word
                words = [".".join(map(str, byte_group)) for byte_group in
                         yield_groups(data, self.group_n_bytes)]
                flow_words += words
            yield flow_words


class NetflowWord2Vec(BasicNetflowFeatureExtractor):
    def __init__(self, vector_size: int = 50, window_size: int = 10, min_count: int = 4,
                 train_method=TrainingMethod.SKIP_GRAM, group_n_bytes=8, **kwargs):
        super(NetflowWord2Vec, self).__init__(**kwargs)
        self.train_method = train_method
        self.model: t.Optional[Word2Vec] = None
        self.vector_size = vector_size
        self.window_size = window_size
        self.min_count = min_count
        self.group_n_bytes = group_n_bytes
        self.training_name = "undefined"

    def fit_extract(self, traffic: TrafficSequence) -> Features:
        self.training_name = traffic.name
        flows = super(NetflowWord2Vec, self)._make_flows(traffic)
        flow_features = super(NetflowWord2Vec, self)._extract_flow_features(flows)
        sen_gen = NetflowPayloadSentenceGen(flows, group_n_bytes=self.group_n_bytes)
        logging.info("Start training the w2v model with %s flows", len(flows))
        # inject a word that is not present in the rest of the training data and is later used for unknown words
        not_found_sentence = [["not_found"] * (self.window_size * 2)] * 20
        self.model = Word2Vec(
            sentences=itertools.chain(sen_gen, not_found_sentence),
            min_count=self.min_count,
            size=self.vector_size, window=self.window_size,
            sg=1 if self.train_method is TrainingMethod.SKIP_GRAM else 0
        )
        logging.info("Finished training word2vec model")
        print(self.model.vocabulary)
        w2v_features = self._get_word2vec_features(sen_gen, length=len(flows))
        print(w2v_features.data)
        return flow_features.combine(w2v_features)

    def extract_features(self, traffic: TrafficSequence) -> Features:
        if self.model is None:
            raise RuntimeError("Doc2Vec Model is not yet trained.")
        flows = super(NetflowWord2Vec, self)._make_flows(traffic)
        flow_features = super(NetflowWord2Vec, self)._extract_flow_features(flows)
        sen_gen = NetflowPayloadSentenceGen(flows, self.group_n_bytes)
        logging.info("Start inferring vectors for %s flows", len(flows))
        w2v_features = self._get_word2vec_features(sen_gen, length=len(flows))
        return flow_features.combine(w2v_features)

    def _get_word2vec_features(self, sen_gen, length):
        per_flow_vectors = []
        for sentence in tqdm(sen_gen, total=length):
            word_vectors = [self.model[word] if word in self.model else self.model["not_found"] for word in
                            sentence]
            if len(word_vectors) > 0:
                flow_vector = np.array(word_vectors).mean(axis=0)
            else:
                flow_vector = self.model["not_found"]
            per_flow_vectors.append(flow_vector)
        return Features(
            data=np.array(per_flow_vectors, ndmin=2),
            names=["w2v_%s" % i for i in range(self.vector_size)],
            types=[FeatureType.FLOAT for _ in range(self.vector_size)]
        )

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        BasicNetflowFeatureExtractor.init_parser(parser)
        parser.add_argument("--w2v-vector-size", type=int, default=50, dest="vector_size")
        parser.add_argument("--w2v-window", type=int, default=5, dest="window")
        parser.add_argument("--w2v-min-count", type=int, default=4, dest="min_count")
        parser.add_argument("--w2v-train-method", choices=[t.value for t in TrainingMethod],
                            default=TrainingMethod.SKIP_GRAM,
                            dest="train_method")
        parser.add_argument("--w2v-group-bytes", type=int, dest="group_bytes", default=8)

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return NetflowWord2Vec(vector_size=args.vector_size, train_method=TrainingMethod(args.train_method),
                               group_n_bytes=args.group_bytes,
                               window_size=args.window, min_count=args.min_count,
                               flow_timeout=args.flow_timeout, subflow_timeout=args.subflow_timeout,
                               verbose=args.verbose,
                               modes=[FeatureSetMode(v) for v in args.nf_mode])

    def __str__(self):
        return self.get_id()

    def get_id(self) -> str:
        return f"FlowWord2Vec({self.model}, training_sequence={self.training_name}, " \
               f"method={self.train_method}; params={self.get_db_params_dict()})"

    @staticmethod
    def get_name() -> str:
        return "flows_word2vec"

    def get_db_params_dict(self):
        base = super(NetflowWord2Vec, self).get_db_params_dict()
        base.update({
            "vector_size": self.vector_size,
            "window_size": self.window_size,
            "min_count": self.min_count,
            "training_method": self.train_method.value,
            "group_n_bytes": self.group_n_bytes
        })
        return base
