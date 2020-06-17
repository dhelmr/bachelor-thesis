import logging
import os
import typing as t

import dpkt as dpkt
import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

from anomaly_detection.feature_extractors.basic_packet_feature_extractor import BasicPacketFeatureExtractor
from anomaly_detection.types import FeatureExtractor, TrafficType


class PacketInformation(t.NamedTuple):
    payload: bytes
    statistic_features: np.ndarray


class DocumentGenerator:
    def __init__(self, packet_infos: t.List[PacketInformation]):
        self.packet_infos = packet_infos

    def __iter__(self):
        i = 0
        for p in self.packet_infos:
            doc = list(map(lambda byte: str(byte), p))
            tags = [i]
            i += 1
            yield TaggedDocument(doc, tags)


class PacketDoc2Vec(FeatureExtractor):
    def __init__(self):
        self.statistic_features_extractor = BasicPacketFeatureExtractor()
        self.model = None
        self.model_dir = ".packet_doc2vec_cache"
        if not os.path.exists(self.model_dir):
            os.mkdir(self.model_dir)

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        return self.get_features(pcap_file, train_before=True)

    def get_features(self, pcap_file: str, train_before: bool):
        model_file = self.get_model_file(pcap_file)
        if self.model is None and os.path.exists(model_file):
            logging.info("Found model file %s, load...", model_file)
            self.model = Doc2Vec.load(model_file)

        if not train_before and self.model is None:
            raise RuntimeError("Error, Doc2Vec model is not yet trained. Abort.")
        packet_infos = self._read_packets(pcap_file)
        logging.info("Finished loading the packets into memory.")
        payloads, statistics = zip(*packet_infos)
        doc_gen = DocumentGenerator(payloads)
        if train_before and self.model is None:
            logging.info("Start training doc2vec model")
            self.model = Doc2Vec(doc_gen, vector_size=20, window=5, min_count=4, workers=128)
            logging.info("Finished training doc2vec model")
            self.model.save(open(model_file, "wb"))
            logging.info("Stored doc2vec model to %s", model_file)
        logging.info("Infer vectors...")
        doc2vec_features = [self.model.infer_vector(x.words) for x in doc_gen]
        return np.array(doc2vec_features)  # TODO add statistic features as well

    def _read_packets(self, pcap_file: str) -> t.List[PacketInformation]:
        packet_infos = []
        packets = read_pcap_pcapng(pcap_file)
        progress = 0
        for ts, buf in packets:
            # statistic = self.statistic_features_extractor.analyze_packet(pkt)
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

    def extract_features(self, pcap_file: str) -> np.ndarray:
        return self.get_features(pcap_file, train_before=False)

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        # No dimension reduction was made when extracting the features
        return de_result

    def get_name(self) -> str:
        return "packet_doc2vec"

    def get_model_file(self, pcap: str) -> str:
        return os.path.join(self.model_dir, "doc2vec_%s.model" % os.path.basename(pcap))


def read_pcap_pcapng(file):
    try:
        reader = dpkt.pcapng.Reader(open(file, "rb"))
    except ValueError as e:
        reader = dpkt.pcap.Reader(open(file, "rb"))
    return reader
