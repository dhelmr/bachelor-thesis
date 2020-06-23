import logging
import multiprocessing
import os
import typing as t

import dpkt as dpkt
import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

from anomaly_detection.feature_extractors.basic_packet_feature_extractor import BasicPacketFeatureExtractor
from anomaly_detection.types import FeatureExtractor, TrafficType
from dataset_utils.pcap_utils import read_pcap_pcapng


class PacketInformation(t.NamedTuple):
    payload: bytes
    # TODO this should be removed/refactored, because it is not used, but the currently trained model depends on
    #  its existence
    statistic_features: np.ndarray


class DocumentGenerator:
    def __init__(self, packet_infos: t.List[PacketInformation]):
        self.packet_infos = packet_infos

    def __iter__(self):
        for i in range(len(self.packet_infos)):
            yield self.get(i)

    def get(self, index) -> TaggedDocument:
        words = self.get_words(index)
        tags = [index]
        return TaggedDocument(words, tags)

    def get_words(self, index):
        p = self.packet_infos[index]
        doc = list(map(lambda byte: str(byte), p))
        return doc


class PacketDoc2Vec(FeatureExtractor):
    def __init__(self):
        self.statistic_features_extractor = BasicPacketFeatureExtractor()
        self.model = None
        self.model_dir = ".packet_doc2vec_cache"
        if not os.path.exists(self.model_dir):
            os.mkdir(self.model_dir)

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        if self.model is not None:
            raise RuntimeError("Doc2Vec model is already trained and loaded in memory, abort.")
        model_file = self.get_model_file(pcap_file)
        if os.path.exists(model_file):
            logging.info("Found model file %s, load...", model_file)
            self.model = Doc2Vec.load(model_file)
        else:
            doc_gen = self._make_doc_gen(pcap_file)
            logging.info("Start training doc2vec model")
            self.model = Doc2Vec(doc_gen, vector_size=20, window=5, min_count=4, workers=128)
            logging.info("Finished training doc2vec model")
            self.model.save(open(model_file, "wb"))
            logging.info("Stored doc2vec model to %s", model_file)
        d2v_features = self.model.docvecs.vectors_docs
        return self._append_statistical_features(pcap_file, d2v_features)

    def _read_packets(self, pcap_file: str) -> t.List[PacketInformation]:
        packet_infos = []
        packets = read_pcap_pcapng(pcap_file)
        progress = 0
        for ts, buf in packets:
            statistic = self.statistic_features_extractor.analyze_packet(ts, buf)
            eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) is dpkt.ip.IP:
                ip = eth.data
                payload = bytes(ip.data)
            else:
                payload = bytes()
            packet_infos.append(PacketInformation(payload, np.array([])))
            progress += 1
            if progress % 1_000_000 == 0:
                logging.info("Processed %s packets", progress)
        return packet_infos

    def _make_doc_gen(self, pcap_file) -> DocumentGenerator:
        packet_infos = self._read_packets(pcap_file)
        logging.info("Finished loading the packets into memory.")
        payloads, statistics = zip(*packet_infos)
        doc_gen = DocumentGenerator(payloads)
        return doc_gen

    def extract_features(self, pcap_file: str) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Error, Doc2Vec model is not yet trained. Abort.")
        doc_gen = self._make_doc_gen(pcap_file)
        workers = MultiThreadedDoc2VecInferer(self.model, doc_gen)
        d2v_features = workers.infer_vectors()
        return self._append_statistical_features(pcap_file, np.array(d2v_features))

    def _append_statistical_features(self, pcap_file: str, d2v_features: np.ndarray) -> np.ndarray:
        # TODO feed already read-in packets (buf)
        meta_features = self.statistic_features_extractor.extract_features(pcap_file)
        return np.hstack((d2v_features, meta_features))

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        # No dimension reduction was made when extracting the features
        return de_result

    def get_name(self) -> str:
        return "packet_doc2vec"

    def get_model_file(self, pcap: str) -> str:
        return os.path.join(self.model_dir, "doc2vec_%s.model" % os.path.basename(pcap))


class MultiThreadedDoc2VecInferer:
    def __init__(self, model: Doc2Vec, doc_gen: DocumentGenerator, n_proc=None):
        if n_proc is None:
            n_proc = os.cpu_count()
        self.n_proc = n_proc
        self.model = model
        self.doc_gen = doc_gen
        self.batch_size = 100_000

    def infer_vectors(self):
        logging.info("Infer vectors with %s processes...", self.n_proc)
        pool = multiprocessing.Pool(self.n_proc)
        features = []
        # Read in the indexes portion-wise due to a bug in python < 3.8 when sending large lists with pool connections
        # See https://bugs.python.org/issue35152
        for batch_indexes in self.iter_batch_ranges():
            batch_features = pool.map(self._infer, batch_indexes)
            features += batch_features
        return features

    def _infer(self, doc_index):
        words = self.doc_gen.get_words(doc_index)
        vector = self.model.infer_vector(words)
        if (doc_index + 1) % 10_000 == 0:
            logging.info("Inferred %s vectors", doc_index)
        return vector

    def iter_batch_ranges(self):
        start_index = 0
        total_length = len(self.doc_gen.packet_infos)
        while True:
            end = min(start_index + self.batch_size, total_length)
            yield range(start_index, end)
            start_index = end
            if start_index >= total_length:
                break


class LogIter:
    def __init__(self, base_iter, format="Processed %s items", log_after=10_000):
        self.base_iter = base_iter
        self.format = format
        self.log_after = log_after

    def __iter__(self):
        process = 0
        for item in self.base_iter:
            process += 1
            if process % self.log_after == 0:
                logging.info(self.format, process)
            yield item
