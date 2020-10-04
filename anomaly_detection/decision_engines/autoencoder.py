import argparse
import pickle
import typing as t
import uuid

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from anomaly_detection.types import DecisionEngine, TrafficType


class AutoencoderDE(DecisionEngine):
    def __init__(self, **kwargs):
        self.training_epochs = 50
        self.training_batch = 256
        self.threshold = None
        self.autoencoder = None
        if "threshold" in kwargs:
            self.threshold = kwargs["threshold"]
        if "autoencoder" in kwargs:
            self.autoencoder = kwargs["autoencoder"]

    def init_model(self, input_dim: int, encoding_dim: int):
        self.autoencoder = keras.Sequential(
            [
                layers.Dense(input_dim, activation="relu", name="input"),
                layers.Dense(encoding_dim, activation="relu", name="encoded"),
                layers.Dense(input_dim, name="decoded"),
            ]
        )
        self.autoencoder.compile(optimizer='adam', loss="mse")

    def fit(self, traffic_data: np.ndarray, traffic_type: TrafficType):
        dim = len(traffic_data[0])
        self.init_model(input_dim=dim, encoding_dim=round(dim / 2) + 1)
        self.autoencoder.fit(traffic_data, traffic_data,
                             epochs=self.training_epochs,
                             batch_size=self.training_batch,
                             shuffle=True)
        # Get train MAE loss.
        pred = self.autoencoder.predict(traffic_data)
        train_mae_loss = np.mean(np.abs(pred - traffic_data), axis=1)
        self.threshold = np.percentile(train_mae_loss, 95)

    def classify(self, traffic_data: np.ndarray) -> t.Sequence[TrafficType]:
        if self.autoencoder is None or self.threshold is None:
            raise RuntimeError("Autoencoder is not trained yet.")
        predicted = self.autoencoder.predict(traffic_data)
        test_mae_loss = np.mean(np.abs(predicted - traffic_data), axis=1)
        test_mae_loss = test_mae_loss.reshape((-1))
        classifications = [TrafficType.ATTACK if loss > self.threshold
                           else TrafficType.BENIGN
                           for loss in test_mae_loss]
        return classifications

    def get_name(self) -> str:
        return "autoencoder"  # TODO incorporate params

    def serialize(self) -> str:
        """ Saves the model using keras' own method to the file system and remember its id for reloading it later"""
        id = self.get_name() + "_" + uuid.uuid4().__str__()
        self.autoencoder.save(id)
        return pickle.dumps({
            "id": id,
            "threshold": self.threshold
        })

    @staticmethod
    def deserialize(serialized):
        deserialized = pickle.loads(serialized)
        model = tf.keras.models.load_model(deserialized["id"])
        threshold = deserialized["threshold"]
        return AutoencoderDE(autoencoder=model, threshold=threshold)


def create_parser(prog_name):
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    return parser
