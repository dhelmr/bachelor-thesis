import logging
import typing as t

import dpkt as dpkt
import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument

from anomaly_detection.feature_extractors.basic_packet_feature_extractor import BasicPacketFeatureExtractor
from anomaly_detection.types import FeatureExtractor, TrafficType


class PacketInformation(t.NamedTuple):
    payload: bytes
    statistic_features: np.ndarray


class PacketDoc2Vec(FeatureExtractor):
    def __init__(self):
        self.statistic_features_extractor = BasicPacketFeatureExtractor()
        self.model = None

    def fit_extract(self, pcap_file: str) -> np.ndarray:
        return self.get_features(pcap_file, train_before=True)

    def get_features(self, pcap_file: str, train_before: bool):
        if not train_before and self.model is None:
            raise RuntimeError("Error, Doc2Vec model is not yet trained. Abort.")
        packet_infos = self._read_packets(pcap_file)
        payloads, statistics = zip(*packet_infos)
        payloads = self._gen_documents(payloads)
        tagged_docs = [TaggedDocument(pkt_info, [i]) for i, pkt_info in enumerate(payloads)]
        if train_before:
            logging.info("Start training doc2vec model")
            self._train_model(tagged_docs)
        doc2vec_features = list(map(lambda x: self.model.infer_vector(x), payloads))
        return np.array(doc2vec_features)  # TODO add statistic features as well

    def _train_model(self, documents):
        self.model = Doc2Vec(documents, vector_size=5, window=2, min_count=1, workers=4)

    def _gen_documents(self, payloads: t.List[bytes]):
        """
        Creates for each payload a list of its byte's integer representations, like ["123","23","0"]
        :param payloads:
        :return:
        """
        return [list(map(lambda byte: str(byte), payload)) for payload in payloads]

    def _read_packets(self, pcap_file: str) -> t.List[PacketInformation]:
        packet_infos = []
        packets = dpkt.pcapng.Reader(open(pcap_file, "rb"))
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
            if progress % 50_000 == 0:
                logging.info("Processed %s packets", progress)
        return packet_infos

    def extract_features(self, pcap_file: str) -> np.ndarray:
        return self.get_features(pcap_file, train_before=False)

    def map_backwards(self, pcap_file: str, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        # No dimension reduction was made when extracting the features
        return de_result

    def get_name(self) -> str:
        return "packet_doc2vec"
