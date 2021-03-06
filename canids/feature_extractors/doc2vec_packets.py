import argparse
import functools
import logging
import multiprocessing
import os
import struct
import sys
import typing as t

import dpkt as dpkt
import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

from canids.feature_extractors.basic_packet_feature_extractor import (
    BasicPacketFeatureExtractor,
)
from canids.types import FeatureExtractor, TrafficType, TrafficSequence

logger = logging.getLogger()


class PacketInformation(t.NamedTuple):
    payload: bytes
    statistical_features: np.ndarray


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
        self.model: Doc2Vec = None
        self.model_dir = ".packet_doc2vec_cache"
        if not os.path.exists(self.model_dir):
            os.mkdir(self.model_dir)

    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        if self.model is not None:
            raise RuntimeError(
                "Doc2Vec model is already trained and loaded in memory, abort."
            )
        packet_infos = self._read_packets(traffic)
        doc_gen = self._make_doc_gen(packet_infos)
        logging.info("Start training doc2vec model")
        self.model = Doc2Vec(
            doc_gen, vector_size=20, window=5, min_count=4, workers=128
        )
        logging.info("Finished training doc2vec model")
        d2v_features = self.model.docvecs.vectors_docs
        return self._append_statistical_features(packet_infos, d2v_features)

    def _read_packets(self, traffic: TrafficSequence) -> t.List[PacketInformation]:
        packet_infos = []
        progress = 0
        for packet in traffic.packet_reader:
            ts, buf = packet
            statistic = self.statistic_features_extractor.analyze_packet(packet)
            eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) is dpkt.ip.IP:
                ip = eth.data
                payload = bytes(ip.data)
            else:
                payload = bytes()
            statistical_features = self.statistic_features_extractor.analyze_packet(
                packet
            )
            packet_infos.append(PacketInformation(payload, statistical_features))
            progress += 1
            if progress % 1_000_000 == 0:
                logging.info("Loaded %s packets", progress)
        return packet_infos

    def _append_statistical_features(
        self, packet_infos: t.List[PacketInformation], d2v_features: np.ndarray
    ) -> np.ndarray:
        _, meta_features = zip(*packet_infos)
        return np.hstack((d2v_features, meta_features))

    def _make_doc_gen(
        self, packet_infos: t.List[PacketInformation]
    ) -> DocumentGenerator:
        logging.info("Finished loading the packets into memory.")
        payloads, _ = zip(*packet_infos)
        doc_gen = DocumentGenerator(payloads)
        return doc_gen

    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Error, Doc2Vec model is not yet trained. Abort.")
        packet_infos = self._read_packets(traffic)
        doc_gen = self._make_doc_gen(packet_infos)
        workers = MultiThreadedDoc2VecInferer(self.model, doc_gen)
        d2v_features = workers.infer_vectors()
        return self._append_statistical_features(packet_infos, d2v_features)

    def map_backwards(
        self, pcap_file: str, de_result: t.Sequence[TrafficType]
    ) -> t.Sequence[TrafficType]:
        # No dimension reduction was made when extracting the features
        return de_result

    def get_name(self) -> str:
        return "packet_doc2vec"

    @staticmethod
    def init_parser(parser: argparse.ArgumentParser):
        pass

    @staticmethod
    def init_by_parsed(args: argparse.Namespace):
        return PacketDoc2Vec()

    def __str__(self):
        return f"PacketDoc2Vec({self.model})"


global_parallel_model: Doc2Vec


class MultiThreadedDoc2VecInferer:
    def __init__(self, model: Doc2Vec, doc_gen: DocumentGenerator, n_proc=None):
        if n_proc is None:
            n_proc = multiprocessing.cpu_count()
        self.n_proc = n_proc
        self.model = model
        self.model.delete_temporary_training_data(
            keep_doctags_vectors=False, keep_inference=True
        )
        global global_parallel_model
        global_parallel_model = self.model
        self.doc_gen = doc_gen
        self.batch_size = 1000

    def infer_vectors(self):
        logging.info("Infer vectors with %s processes...", self.n_proc)
        features = []
        # Read in the indexes portion-wise due to a bug in python < 3.8 when sending large lists with pool connections
        # See https://bugs.python.org/issue35152
        i = 0
        for batch_indexes in self.iter_batch_ranges():
            logging.info(
                "Infer vector progress: %s perc",
                i * self.batch_size / len(self.doc_gen.packet_infos) * 100,
            )
            with multiprocessing.Pool(self.n_proc) as pool:
                batch_features = pool.map(
                    parallel_infer_vector, self.make_parallel_params(batch_indexes)
                )
            features += batch_features
            i += 1
        return features

    def make_parallel_params(self, iter_range):
        for doc_index in iter_range:
            words = self.doc_gen.get_words(doc_index)
            yield (words,)

    def iter_batch_ranges(self):
        start_index = 0
        total_length = len(self.doc_gen.packet_infos)
        while True:
            end = min(start_index + self.batch_size, total_length)
            yield range(start_index, end)
            start_index = end
            if start_index >= total_length:
                break


def parallel_infer_vector(params):
    words = params[0]
    vector = global_parallel_model.infer_vector(words)
    return vector


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


def patch_mp_connection_bpo_17560():
    """Apply PR-10305 / bpo-17560 connection send/receive max size update

    See the original issue at https://bugs.python.org/issue17560 and
    https://github.com/python/cpython/pull/10305 for the pull request.

    This only supports Python versions 3.3 - 3.7, this function
    does nothing for Python versions outside of that range.

    """
    patchname = "Multiprocessing connection patch for bpo-17560"
    if not (3, 3) < sys.version_info < (3, 8):
        logger.info(
            patchname + " not applied, not an applicable Python version: %s",
            sys.version,
        )
        return

    from multiprocessing.connection import Connection

    orig_send_bytes = Connection._send_bytes
    orig_recv_bytes = Connection._recv_bytes
    if (
        orig_send_bytes.__code__.co_filename == __file__
        and orig_recv_bytes.__code__.co_filename == __file__
    ):
        logger.info(patchname + " already applied, skipping")
        return

    @functools.wraps(orig_send_bytes)
    def send_bytes(self, buf):
        n = len(buf)
        if n > 0x7FFFFFFF:
            pre_header = struct.pack("!i", -1)
            header = struct.pack("!Q", n)
            self._send(pre_header)
            self._send(header)
            self._send(buf)
        else:
            orig_send_bytes(self, buf)

    @functools.wraps(orig_recv_bytes)
    def recv_bytes(self, maxsize=None):
        buf = self._recv(4)
        (size,) = struct.unpack("!i", buf.getvalue())
        if size == -1:
            buf = self._recv(8)
            (size,) = struct.unpack("!Q", buf.getvalue())
        if maxsize is not None and size > maxsize:
            return None
        return self._recv(size)

    Connection._send_bytes = send_bytes
    Connection._recv_bytes = recv_bytes

    logger.info(patchname + " applied")


patch_mp_connection_bpo_17560()
