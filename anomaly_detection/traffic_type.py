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