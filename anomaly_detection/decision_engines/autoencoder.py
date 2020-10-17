import argparse
import os
import pickle
import typing as t
import uuid

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from anomaly_detection.types import DecisionEngine, TrafficType, Features

MODEL_FILE_PATH = ".autoencoders"
POSSIBLE_ACTIVATIONS = ["relu", "sigmoid", "softmax", "softplus",
                        "softsign", "tanh", "selu", "elu", "exponential"]
POSSIBLE_LOSS = ["mse", "mae"]


def init_keras():
    tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)
    if os.path.exists(MODEL_FILE_PATH) and not os.path.isdir(MODEL_FILE_PATH):
        raise FileExistsError("%s already exists and is not a dir!" % MODEL_FILE_PATH)
    if not os.path.exists:
        os.mkdir(MODEL_FILE_PATH)


class AutoencoderDE(DecisionEngine):
    def __init__(self, **kwargs):
        init_keras()
        self.verbose = False
        if "parsed_args" in kwargs:
            parsed = kwargs["parsed_args"]
            self.training_epochs = parsed.training_epochs
            self.training_batch = parsed.training_batch
            self.layers = self.parse_layers(parsed.layers)
            self.activation = parsed.activation
            self.loss = parsed.loss
            self.verbose = parsed.verbose
        else:
            self.threshold = kwargs["threshold"]
            self.autoencoder = kwargs["autoencoder"]
            self.loss = kwargs["loss"]

    def parse_layers(self, layers_pattern: str):
        splitted = layers_pattern.split(",")
        layers = []
        for layer in splitted:
            try:
                n_nodes = int(layer)
            except Exception:
                raise ValueError("Invalid layer, must be a number: %s" % layer)
            layers.append(n_nodes)
        return layers

    def init_model(self, input_dim: int):
        self.autoencoder = keras.Sequential(
            [
                layers.Dense(input_dim, activation=self.activation, name="input"),
                *self.make_hidden_layers(),
                layers.Dense(input_dim, name="decoded"),
            ]
        )
        self.autoencoder.compile(optimizer='adam', loss=self.loss)

    def make_hidden_layers(self):
        return [
            layers.Dense(n_nodes, activation=self.activation, name="hidden_layer-%s" % i)
            for i, n_nodes in enumerate(self.layers)
        ]

    def loss_fn(self, predicted, actual):
        loss_fn = keras.losses.get(self.loss)
        return loss_fn(predicted, actual)

    def fit(self, features: Features, traffic_type: TrafficType):
        data = features.data
        dim = len(data[0])
        self.init_model(input_dim=dim)
        self.autoencoder.fit(data, data,
                             epochs=self.training_epochs,
                             batch_size=self.training_batch,
                             shuffle=True, verbose=self._get_keras_verbose())
        # Get train MAE loss.
        pred = self.autoencoder.predict(data)
        train_mae_loss = self.loss_fn(pred, data)
        self.threshold = np.max(train_mae_loss)

    def classify(self, features: Features) -> t.Sequence[TrafficType]:
        if self.autoencoder is None or self.threshold is None:
            raise RuntimeError("Autoencoder is not trained yet.")
        pred = self.autoencoder.predict(features.data)
        test_losses = self.loss_fn(pred, features.data)
        classifications = [TrafficType.ATTACK if loss > self.threshold
                           else TrafficType.BENIGN
                           for loss in test_losses]
        return classifications

    def _get_keras_verbose(self):
        """Returns the corresponding value that indicates "verbose" behaviour in keras methods"""
        if self.verbose:
            return 1
        else:
            return 0

    def get_name(self) -> str:
        return "autoencoder"  # TODO incorporate params

    def serialize(self) -> str:
        """ Saves the model using keras' own method to the file system and remember its id for reloading it later"""
        id = self.get_name() + "_" + uuid.uuid4().__str__()
        filepath = os.path.join(MODEL_FILE_PATH, id)
        self.autoencoder.save(filepath)
        return pickle.dumps({
            "id": id,
            "threshold": self.threshold,
            "loss": self.loss,
            "activation": self.activation,
            "layers": self.layers
        })

    @staticmethod
    def deserialize(serialized):
        deserialized = pickle.loads(serialized)
        filepath = os.path.join(MODEL_FILE_PATH, deserialized["id"])
        model = tf.keras.models.load_model(filepath)
        threshold = deserialized["threshold"]
        loss = deserialized["loss"]
        return AutoencoderDE(autoencoder=model, threshold=threshold, loss=loss)


def create_parser(prog_name):
    parser = argparse.ArgumentParser(
        prog=prog_name,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--training-epochs", type=int, default=50)
    parser.add_argument("--training-batch", type=int, default=256)
    parser.add_argument("--layers", type=str, default="15,8,15")
    parser.add_argument("--activation", type=str, default=POSSIBLE_ACTIVATIONS[0], choices=POSSIBLE_ACTIVATIONS)
    parser.add_argument("--loss", type=str, default=POSSIBLE_LOSS[0], choices=POSSIBLE_LOSS)
    parser.add_argument("--verbose", action="store_true", default=False)
    return parser
