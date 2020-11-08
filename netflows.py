import argparse

import pandas

from anomaly_detection.feature_extractors.basic_netflow_extractor import BasicNetflowFeatureExtractor
from anomaly_detection.transformers import OneHotEncoder
from anomaly_detection.types import TrafficSequence
from dataset_utils import pcap_utils


class PcapTrafficReader:

    def read(self, pcap_file):
        return TrafficSequence(
            name=pcap_file,
            is_consistent=False,
            ids=[],
            labels=pandas.Series(dtype=float),
            packet_reader=pcap_utils.read_pcap_pcapng(pcap_file, print_progress_after=200)
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help="Pcap file to read", required=True)
    parser.add_argument("-o", "--output", help="CSV output file to write", required=True)
    parser.add_argument("--one-hot", help="Onehot-encode categorial features", action="store_true")
    BasicNetflowFeatureExtractor.init_parser(parser)
    parsed = parser.parse_args()
    fe = BasicNetflowFeatureExtractor.init_by_parsed(parsed)

    traffic = PcapTrafficReader().read(parsed.pcap)
    features = fe.extract_features(traffic)
    if parsed.one_hot:
        onehot_encoder = OneHotEncoder()
        features = onehot_encoder.fit_transform(features)
    df = features.as_pandas()
    df.to_csv(parsed.output)
    print(df)


if __name__ == '__main__':
    main()
