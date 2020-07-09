import argparse
import typing as t
from abc import ABC, abstractmethod, ABCMeta
from enum import Enum
from typing import NamedTuple

import numpy as np
import pandas as pd


class TrafficType(Enum):
    BENIGN = 0
    ATTACK = 1
    UNKNOWN = 2

    def opposite_of(self):
        if self is TrafficType.BENIGN:
            return TrafficType.ATTACK
        elif self is TrafficType.ATTACK:
            return TrafficType.BENIGN
        else:
            return TrafficType.UNKNOWN


class DecisionEngine(ABC):
    __metaclass__ = ABCMeta

    @abstractmethod
    def classify(self, traffic_data: np.ndarray) -> t.Sequence[TrafficType]:
        raise NotImplementedError()

    @abstractmethod
    def fit(self, traffic_data: np.ndarray, traffic_type: TrafficType):
        raise NotImplementedError()

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def serialize(self) -> str:
        raise NotImplementedError()

class Transformer(ABC):
    __metaclass__ = ABCMeta

    @abstractmethod
    def fit(self, traffic_data: np.ndarray):
        raise NotImplementedError()

    @abstractmethod
    def transform(self, traffic_data: np.ndarray):
        raise NotImplementedError()

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError()


Packet = t.Tuple[float, bytes]
PacketReader = t.Iterable[Packet]


class TrafficSequence(NamedTuple):
    name: str
    packet_reader: PacketReader
    ids: t.List[str]
    labels: pd.Series


class TrafficReader(ABC):
    __metaclass__ = ABCMeta

    @abstractmethod
    def read_normal_data(self) -> TrafficSequence:
        raise NotImplementedError()

    @abstractmethod
    def __next__(self) -> TrafficSequence:
        raise NotImplementedError()

    @abstractmethod
    def __iter__(self):
        raise NotImplementedError()


class FeatureExtractor:
    __metaclass__ = ABCMeta

    @abstractmethod
    def fit_extract(self, traffic: TrafficSequence) -> np.ndarray:
        raise NotImplementedError()

    @abstractmethod
    def extract_features(self, traffic: TrafficSequence) -> np.ndarray:
        raise NotImplementedError()

    @abstractmethod
    def map_backwards(self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        raise NotImplementedError()

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def init_parser(parser: argparse.ArgumentParser):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def init_by_parsed(args: argparse.Namespace):
        raise NotImplementedError()


class ClassificationResults(NamedTuple):
    classification_id: str
    traffic_ids: t.Sequence[str]
    predictions: t.Sequence[TrafficType]


class DatasetPreprocessor:
    __metaclass__ = ABCMeta

    @abstractmethod
    def preprocess(self, dataset_path: str):
        raise NotImplementedError()


class DatasetUtils(NamedTuple):
    traffic_reader: t.Callable[[str], TrafficReader]
    preprocessor: t.Callable[[], DatasetPreprocessor]
