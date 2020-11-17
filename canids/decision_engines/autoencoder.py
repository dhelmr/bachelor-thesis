import argparse
import enum
import os
import pickle
import typing as t
import uuid

import numpy as np

tf = None
keras = None

from canids.types import DecisionEngine, TrafficType, Features

MODEL_FILE_PATH = ".autoencoders"
POSSIBLE_ACTIVATIONS = [
    "relu",
    "sigmoid",
    "softmax",
    "softplus",
    "softsign",
    "tanh",
    "selu",
    "elu",
    "exponential",
]
POSSIBLE_LOSS = ["mse", "mae"]


class BatchNormalizationMode(enum.Enum):
    NONE = "none"
    AFTER_ACTIVATION = "after_activation"


class LayerSizeType(enum.Enum):
    FIXED_SIZE = 0
    RELATIVE = 1
    REFERENCE = 2


class LayerDefinition(t.NamedTuple):
    size_type: LayerSizeType
    value: float

    def format(self):

        if self.size_type is LayerSizeType.RELATIVE:
            modifier_char = "*"
        elif self.size_type is LayerSizeType.REFERENCE:
            modifier_char = "#"
        elif self.size_type is LayerSizeType.FIXED_SIZE:
            modifier_char = ""
        else:
            raise ValueError("Unexpected size type %s" % self.size_type)
        return "%s%s" % (modifier_char, self.value)


def init_keras():
    global keras
    global tf

    import tensorflow
    from tensorflow import keras as k

    tf = tensorflow
    keras = k

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
            self.early_stopping_patience = parsed.early_stopping_patience
            self.layers = self.parse_layers(parsed.layers)
            self.activation = parsed.activation
            self.batch_normalization = parsed.batch_normalization
            self.dropout_ratio = parsed.dropout_ratio
            self.loss = parsed.loss
            self.verbose = parsed.verbose
        else:
            self.threshold = kwargs["threshold"]
            self.autoencoder = kwargs["autoencoder"]
            self.loss = kwargs["loss"]
            self.layer_sizes = kwargs["layer_sizes"]
            self.activation = kwargs["activation"]
            self.dropout_ratio = kwargs["dropout_ratio"]
            self.batch_normalization = kwargs["batch_normalization"]
            self.training_epochs = kwargs["training_epochs"]
            self.training_batch = kwargs["training_batch"]
            self.early_stopping_patience = kwargs["early_stopping_patience"]

    @staticmethod
    def parse_layers(layers_pattern) -> t.List[LayerDefinition]:
        splitted = layers_pattern.split(",")
        layers = []
        for layer in splitted:
            if layer[0] == "*":
                # A pattern like "*2" indicates, that the layer should have twice as much nodes as the predecessor
                size_type = LayerSizeType.RELATIVE
                layer = layer[1:]
            elif layer[0] == "#":
                size_type = LayerSizeType.REFERENCE
                layer = layer[1:]
            else:
                size_type = LayerSizeType.FIXED_SIZE
            try:
                value = float(layer)
                if (
                    size_type is LayerSizeType.FIXED_SIZE
                    or size_type is LayerSizeType.REFERENCE
                ):
                    value = int(value)
            except Exception:
                raise ValueError(
                    "Invalid layer of type %s, must be a number: %s"
                    % (size_type.name, layer)
                )
            layers.append(LayerDefinition(size_type, value))
        return layers

    def init_model(self, input_dim: int):
        hidden_layers, self.layer_sizes = self.make_hidden_layers(input_dim)
        self.autoencoder = keras.Sequential(
            [
                keras.layers.Dense(input_dim, activation=self.activation, name="input"),
                *hidden_layers,
                keras.layers.Dense(input_dim, name="decoded"),
            ]
        )
        self.autoencoder.compile(optimizer="adam", loss=self.loss)

    def make_hidden_layers(self, input_dim):
        hidden_layers = []
        sizes = [input_dim]
        self._append_dropout_layer(hidden_layers)
        for i, definition in enumerate(self.layers):
            if definition.size_type is LayerSizeType.FIXED_SIZE:
                size = int(definition.value)
            elif definition.size_type is LayerSizeType.RELATIVE:
                size = round(definition.value * sizes[-1])
            elif definition.size_type is LayerSizeType.REFERENCE:
                size = sizes[int(definition.value)]
            else:
                raise ValueError("Unexpected value: %s" % definition.size_type)
            hidden_layers.append(
                keras.layers.Dense(
                    size, activation=self.activation, name="hidden_layer-%s" % i
                )
            )
            self._append_normalization_layer(hidden_layers)
            self._append_dropout_layer(hidden_layers)
            sizes.append(size)
        sizes.append(input_dim)
        return hidden_layers, sizes

    def _append_dropout_layer(self, layer_list):
        if self.dropout_ratio < 0:
            return
        layer_list.append(keras.layers.Dropout(self.dropout_ratio))

    def _append_normalization_layer(self, layer_list):
        if self.batch_normalization is BatchNormalizationMode.NONE:
            return
        layer_list.append(keras.layers.BatchNormalization())

    def loss_fn(self, predicted, actual):
        loss_fn = keras.losses.get(self.loss)
        return loss_fn(predicted, actual)

    def fit(self, features: Features, traffic_type: TrafficType):
        data = features.data
        dim = len(data[0])
        callbacks = []
        if self.early_stopping_patience >= 0:
            from tensorflow.python.keras.callbacks import EarlyStopping

            callbacks.append(
                EarlyStopping(
                    patience=self.early_stopping_patience,
                    monitor="loss",
                    mode="min",
                    restore_best_weights=True,
                )
            )

        self.init_model(input_dim=dim)
        self.autoencoder.fit(
            data,
            data,
            epochs=self.training_epochs,
            batch_size=self.training_batch,
            callbacks=callbacks,
            shuffle=True,
            verbose=self._get_keras_verbose(),
        )
        # Get train MAE loss.
        pred = self.autoencoder.predict(data)
        train_mae_loss = self.loss_fn(pred, data)
        self.threshold = np.max(train_mae_loss)

    def classify(self, features: Features) -> t.Sequence[TrafficType]:
        if self.autoencoder is None or self.threshold is None:
            raise RuntimeError("Autoencoder is not trained yet.")
        pred = self.autoencoder.predict(features.data)
        test_losses = self.loss_fn(pred, features.data)
        classifications = [
            TrafficType.ATTACK if loss > self.threshold else TrafficType.BENIGN
            for loss in test_losses
        ]
        return classifications

    def _get_keras_verbose(self):
        """Returns the corresponding value that indicates "verbose" behaviour in keras methods"""
        if self.verbose:
            return 1
        else:
            return 0

    @staticmethod
    def get_name() -> str:
        return "autoencoder"

    def __str__(self):

        return (
            f"Autoencoder(layer_sizes={self.layer_sizes}, loss={self.loss}, act={self.activation},"
            f" train_batch={self.training_batch}, train_epochs={self.training_epochs})"
        )

    def serialize(self) -> bytes:
        """ Saves the model using keras' own method to the file system and remember its id for reloading it later"""
        id = self.get_name() + "_" + uuid.uuid4().__str__()
        filepath = os.path.join(MODEL_FILE_PATH, id)
        self.autoencoder.save(filepath)
        return pickle.dumps(
            {
                "id": id,
                "threshold": self.threshold,
                "loss": self.loss,
                "activation": self.activation,
                "layers": self.layers,
                "layer_sizes": self.layer_sizes,
                "training_batch": self.training_batch,
                "training_epochs": self.training_epochs,
                "early_stopping_patience": self.early_stopping_patience,
                "batch_normalization": self.batch_normalization,
                "dropout_ratio": self.dropout_ratio,
            }
        )

    @staticmethod
    def deserialize(serialized):
        init_keras()
        deserialized = pickle.loads(serialized)
        filepath = os.path.join(MODEL_FILE_PATH, deserialized["id"])
        model = tf.keras.models.load_model(filepath)
        threshold = deserialized["threshold"]
        loss = deserialized["loss"]
        layer_sizes = deserialized["layer_sizes"]
        activation = deserialized["activation"]
        training_epochs = deserialized["training_epochs"]
        training_batch = deserialized["training_batch"]
        dropout_ratio = deserialized["dropout_ratio"]
        batch_normalization = deserialized["batch_normalization"]
        return AutoencoderDE(
            autoencoder=model,
            threshold=threshold,
            loss=loss,
            layer_sizes=layer_sizes,
            activation=activation,
            training_epochs=training_epochs,
            training_batch=training_batch,
            early_stopping_patience=deserialized["early_stopping_patience"],
            dropout_ratio=dropout_ratio,
            batch_normalization=batch_normalization,
        )

    def get_db_params_dict(self):
        layer_pattern = ",".join([layer.format() for layer in self.layers])
        return {
            "threshold": self.threshold,
            "layer_sizes": self.layer_sizes,
            "loss": self.loss,
            "layers": layer_pattern,
            "activation": self.activation,
            "training_batch": self.training_batch,
            "training_epochs": self.training_epochs,
            "early_stopping_patience": self.early_stopping_patience,
            "batch_normalization": self.batch_normalization.value,
            "dropout_ratio": self.dropout_ratio,
        }

    @staticmethod
    def create_parser(prog_name):
        parser = argparse.ArgumentParser(
            prog=prog_name, formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument("--training-epochs", type=int, default=50)
        parser.add_argument("--training-batch", type=int, default=256)
        parser.add_argument("--early-stopping-patience", type=int, default=-1)
        parser.add_argument("--layers", type=str, default="*0.7,*0.8,#1")
        parser.add_argument(
            "--activation",
            type=str,
            default=POSSIBLE_ACTIVATIONS[0],
            choices=POSSIBLE_ACTIVATIONS,
        )
        parser.add_argument(
            "--loss", type=str, default=POSSIBLE_LOSS[0], choices=POSSIBLE_LOSS
        )
        parser.add_argument("--dropout-ratio", type=float, default=-1)
        parser.add_argument(
            "--batch-normalization",
            type=lambda x: BatchNormalizationMode(x),
            default=BatchNormalizationMode.NONE,
        )
        parser.add_argument("--verbose", action="store_true", default=False)
        return parser
