import argparse
import pickle
import typing as t
from abc import ABC, abstractmethod, ABCMeta
from enum import Enum
from typing import NamedTuple

import numpy as np
import pandas
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


Packet = t.Tuple[float, bytes]
PacketReader = t.Iterable[Packet]


class TrafficSequence(NamedTuple):
    name: str
    packet_reader: PacketReader
    ids: t.List[str] = []
    labels: pd.Series = pandas.Series()
    parts: t.Dict[str, t.List[str]] = []
    is_consistent: bool = True

    def copy_with(self, **modifying_args):
        new_params = self._asdict()
        new_params.update(modifying_args)
        return TrafficSequence(**new_params)

class TrafficReader(ABC):
    __metaclass__ = ABCMeta

    def __init__(self, directory: str, subset: str):
        self.dataset_dir = directory
        self.subset_name = subset

    @abstractmethod
    def read_normal_data(self) -> TrafficSequence:
        raise NotImplementedError()

    @abstractmethod
    def __iter__(self) -> t.Iterable[TrafficSequence]:
        raise NotImplementedError()

    def get_train_set_name(self):
        return self.subset_name

    def get_testset_name(self):
        return self.subset_name

    @abstractmethod
    def get_dataset_name(self):
        raise NotImplementedError()

class FeatureType(Enum):
    INT = 0
    FLOAT = 1
    CATEGORIAL = 2
    BINARY = 3


class Features(NamedTuple):
    names: t.List[str]
    types: t.List[FeatureType]
    data: np.ndarray

    def validate(self):
        if len(self.names) != len(self.types) or (len(self.data) >= 0 and len(self.data[0]) != len(self.types)):
            raise ValueError("Lengths of features names, feature types or data do not match!")

    def as_pandas(self, copy: bool = False) -> pandas.DataFrame:
        if copy is True:
            data = self.data.copy()
        else:
            data = self.data
        return pandas.DataFrame(data, columns=self.names)

    @staticmethod
    def from_pandas(df: pandas.DataFrame, types: t.List[FeatureType]) -> "Features":
        return Features(
            data=df.values,
            types=types,
            names=df.columns.tolist()
        )

    def with_data(self, data):
        return Features(
            data=data,
            types=self.types,
            names=self.names
        )

    def combine(self, other_features: "Features"):
        return Features(
            data=np.hstack((self.data, other_features.data)),
            types=self.types + other_features.types,
            names=self.names + other_features.names
        )


class FeatureExtractor:
    __metaclass__ = ABCMeta

    @abstractmethod
    def fit_extract(self, traffic: TrafficSequence) -> Features:
        raise NotImplementedError()

    @abstractmethod
    def extract_features(self, traffic: TrafficSequence) -> Features:
        raise NotImplementedError()

    @abstractmethod
    def map_backwards(self, traffic: TrafficSequence, de_result: t.Sequence[TrafficType]) -> t.Sequence[TrafficType]:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_name() -> str:
        raise NotImplementedError()

    def get_id(self) -> str:
        return str(self.__hash__())

    @staticmethod
    @abstractmethod
    def init_parser(parser: argparse.ArgumentParser):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def init_by_parsed(args: argparse.Namespace):
        raise NotImplementedError()

    def get_db_params_dict(self):
        raise NotImplementedError()


class Transformer(ABC):
    __metaclass__ = ABCMeta

    @abstractmethod
    def fit_transform(self, features: Features) -> Features:
        raise NotImplementedError()

    @abstractmethod
    def transform(self, traffic_data: Features) -> Features:
        raise NotImplementedError()

    @abstractmethod
    def get_name(self) -> str:
        raise NotImplementedError()


class DecisionEngine(ABC):
    __metaclass__ = ABCMeta

    @abstractmethod
    def classify(self, features: Features, ) -> t.Sequence[TrafficType]:
        raise NotImplementedError()

    @abstractmethod
    def fit(self, features: Features, traffic_type: TrafficType):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def get_name() -> str:
        raise NotImplementedError()

    def serialize(self) -> bytes:
        return pickle.dumps(self)

    @staticmethod
    def deserialize(serialized):
        return pickle.loads(serialized)

    @abstractmethod
    def get_db_params_dict(self):
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def create_parser(prog_name) -> argparse.ArgumentParser:
        raise NotImplementedError()


class ClassificationResults(NamedTuple):
    classification_id: str
    traffic_ids: t.Sequence[str]
    predictions: t.Sequence[TrafficType]


class DatasetPreprocessor:
    __metaclass__ = ABCMeta

    @abstractmethod
    def preprocess(self, dataset_path: str, additional_args: t.List[str]):
        raise NotImplementedError()


class DatasetUtils(NamedTuple):
    default_path: str
    traffic_reader: t.Callable[[str, str], TrafficReader]
    preprocessor: t.Callable[[], DatasetPreprocessor]
    print_stats: t.Callable[[str], None]


class ParsingException(Exception):
    pass
