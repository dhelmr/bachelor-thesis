import typing as t
from abc import ABC, abstractmethod, ABCMeta
import numpy as np
from collections import namedtuple
from enum import Enum


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


TrafficSequence = namedtuple("TrafficSequence", "name traffic labels")


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
