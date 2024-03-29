import logging
import os
from abc import ABC
from typing import Tuple, List

import pandas
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler, MinMaxScaler

from canids.types import Transformer, Features, FeatureType


class ScikitTransformer(Transformer, ABC):
    def __init__(self, scaler, name):
        self._scaler = scaler
        self._name = name

    def fit_transform(self, features: Features) -> Features:
        self._scaler.fit(features.data)
        return self.transform(features)

    def transform(self, features: Features) -> Features:
        data = self._scaler.transform(features.data)
        names, types = self.transform_feature_type_names(features)
        features = Features(data=data, names=names, types=types)
        features.validate()
        return features

    def get_name(self):
        return self._name

    def transform_feature_type_names(
        self, features
    ) -> Tuple[List[str], List[FeatureType]]:
        return features.names, features.types


class StandardScalerTransformer(ScikitTransformer):
    def __init__(self):
        super().__init__(scaler=StandardScaler(), name="standard_scaler")


class MinMaxScalerTransformer(ScikitTransformer):
    def __init__(self):
        super().__init__(scaler=MinMaxScaler(), name="minmax_scaler")


class PCATransformer(ScikitTransformer):
    def __init__(self, n_components):
        super().__init__(
            scaler=PCA(n_components=n_components), name="pca_reducer_%s" % n_components
        )
        self.n_components = n_components

    def transform_feature_type_names(
        self, features
    ) -> Tuple[List[str], List[FeatureType]]:
        names = ["pca_%s" % i for i in range(self.n_components)]
        types = [FeatureType.FLOAT for _ in range(self.n_components)]
        return names, types


class OneHotEncoder(Transformer):
    def __init__(self):
        self.feature_values = dict()

    def fit_transform(self, features: Features) -> Features:
        df = features.as_pandas(copy=False)
        cat_columns = [
            features.names[i]
            for i, tf in enumerate(features.types)
            if tf == FeatureType.CATEGORIAL
        ]
        for name in cat_columns:
            values = set(df[name].tolist())
            logging.debug("Got values %s for feature %s: ", values, name)
            self.feature_values[name] = list(values)
        return self._transform_df(df, features)

    def transform(self, features: Features) -> Features:
        df = features.as_pandas(copy=False)
        return self._transform_df(df, features)

    def _transform_df(
        self, df: pandas.DataFrame, original_features: Features
    ) -> Features:
        new_types = []
        for col_name, values in self.feature_values.items():
            for value in values:
                new_col_name = col_name + "_ohe_" + str(value)
                df[new_col_name] = df[col_name].apply(lambda x: 1 if x == value else 0)
                new_types.append(FeatureType.BINARY)
            df.drop(col_name, axis=1, inplace=True)
        types = [
            original_features.types[i]
            for i, n in enumerate(original_features.names)
            if n not in self.feature_values.keys()
        ] + new_types
        return Features.from_pandas(df, types)

    def get_name(self):
        return "one_hot_encoder"


class FixedFeatureNameFilter(Transformer):
    def __init__(self):
        self.feature_file_name = "fixed_features.txt"
        self.features = self._load_features(self.feature_file_name)

    def _load_features(self, feature_file_name):
        if os.path.exists(feature_file_name):
            path = feature_file_name
        else:
            relative_to_file = os.path.join(
                os.path.dirname(__file__), feature_file_name
            )
            if os.path.exists(relative_to_file):
                path = relative_to_file
            else:
                raise ValueError(
                    "%s cannot be found. It must be placed either at %s or at the current directory."
                    % (feature_file_name, relative_to_file)
                )
        with open(path, "r") as f:
            text = f.read()
        features = [line.strip() for line in text.split("\n") if line.strip() != ""]
        as_set = set(features)
        if len(features) != len(as_set):
            raise ValueError("Found duplicate feature names in %s. Abort." % path)
        return as_set

    def fit_transform(self, features: Features) -> Features:
        return self.transform(features)

    def transform(self, features: Features) -> Features:
        indexes_to_keep = []
        remove_indexes = []
        for i, name in enumerate(features.names):
            if name in self.features:
                indexes_to_keep.append(i)
            else:
                remove_indexes.append(i)
        filtered_data = features.as_pandas()
        filtered_data.drop(columns=filtered_data.columns[remove_indexes], inplace=True)
        indexes_to_keep = set(indexes_to_keep)
        filtered_types = [
            f_type for i, f_type in enumerate(features.types) if i in indexes_to_keep
        ]
        filtered_features = Features.from_pandas(df=filtered_data, types=filtered_types)
        return filtered_features

    def get_name(self) -> str:
        return "fixed_feature_name_filter"
