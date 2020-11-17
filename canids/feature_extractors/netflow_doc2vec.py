import argparse
import logging
import typing as t

import numpy as np
from gensim.models.doc2vec import TaggedDocument, Doc2Vec
from tqdm import tqdm

from canids.feature_extractors.basic_netflow_extractor import (
    BasicNetflowFeatureExtractor,
    NetFlow,
)
from canids.types import TrafficSequence


class NetflowPayloadDocGen:
    def __init__(self, flows: t.List[NetFlow]):
        self.flows = flows

    def __iter__(self) -> t.Iterable[TaggedDocument]:
        for i in range(len(self.flows)):
            flow = self.flows[i]
            flow_words = []
            for ts, buffer in flow.packets:
                words = list(map(lambda byte: str(byte), buffer)) + ["."]
                flow_words += words
            tags = [i]
            yield TaggedDocument(flow_words, tags)


class NetflowDoc2Vec(BasicNetflowFeatureExtractor):
    def __init__(
        self,
        vector_size: int = 20,
        window_size: int = 5,
        min_count: int = 4,
        workers: int = 128,
        **kwargs,
    ):
        super(NetflowDoc2Vec, self).__init__(**kwargs)
        self.model: t.Optional[Doc2Vec] = None
        self.vector_size = vector_size
        self.window_size = window_size
        self.min_count = min_count
        self.workers = workers

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        flows = super(NetflowDoc2Vec, self)._make_flows(traffic)
        flow_features = super(NetflowDoc2Vec, self)._extract_flow_features(flows)
        doc_gen = NetflowPayloadDocGen(flows)
        logging.info("Start training the doc2vec model with %s flows", len(flows))
        self.model = Doc2Vec(
            doc_gen,
            vector_size=self.vector_size,
            window=self.window_size,
            min_count=self.min_count,
            workers=self.workers,
        )
        logging.info("Finished training doc2vec model")
        d2v_features = self.model.docvecs.vectors_docs
        return np.hstack((flow_features, d2v_features))

    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Doc2Vec Model is not yet trained.")
        flows = super(NetflowDoc2Vec, self)._make_flows(traffic)
        flow_features = super(NetflowDoc2Vec, self)._extract_flow_features(flows)
        doc_gen = NetflowPayloadDocGen(flows)
        logging.info("Start inferring vectors for %s flows", len(flows))
        d2v_features = []
        for doc in tqdm(doc_gen, total=len(flows)):
            flow_features = self.model.infer_vector(doc.words)
            d2v_features.append(flow_features)
        return np.hstack((flow_features, d2v_features))

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        BasicNetflowFeatureExtractor.init_parser(parser)
        parser.add_argument(
            "--d2v-vector-size", type=int, default=20, dest="vector_size"
        )
        parser.add_argument("--d2v-workers", type=int, default=64, dest="workers")
        parser.add_argument("--d2v-window", type=int, default=5, dest="min_count")
        parser.add_argument("--d2v-min-count", type=int, default=4, dest="window")

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return NetflowDoc2Vec(
            vector_size=args.vector_size,
            workers=args.workers,
            window_size=args.window,
            min_count=args.min_count,
            flow_timeout=args.flow_timeout,
            subflow_timeout=args.subflow_timeout,
        )

    def __str__(self):
        return f"NetflowDoc2Vec({self.model})"
