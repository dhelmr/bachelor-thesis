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


class Preprocessor(ABC):
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


class TrafficSequence(NamedTuple):
    name: str
    traffic: pd.DataFrame
    labels: pd.DataFrame


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