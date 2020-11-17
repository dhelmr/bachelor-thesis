from typing import NamedTuple

import pandas as pd


class ModelInfo(NamedTuple):
    model_info: pd.Series
    de_name: str
    de_info: pd.Series
    fe_name: str
    fe_info: pd.Series

    def pretty(self):
        return (
            self.model_info.__str__()
            + "\n\n"
            + "Decision Engine: "
            + self.de_name
            + "\n"
            + self.de_info.drop(columns=["model_id"]).T.__str__()
            + "\n\n"
            + "Feature Extractor: "
            + self.fe_name
            + "\n"
            + self.fe_info.drop(columns=["model_id"]).T.__str__()
        )


def get_info(db, model_id: str, model_infos=None, detailed_info=True) -> ModelInfo:
    if model_infos is None:
        infos = db.get_model_infos()
    else:
        infos = model_infos
    model_info = infos[infos.index == model_id]
    if len(model_info) == 0:
        raise ValueError("Model ID not found %s" % model_id)
    de_name = model_info["decision_engine"][0]
    fe_name = model_info["feature_extractor"][0]
    if not detailed_info:
        de_info = pd.Series()
        fe_info = pd.Series()
    else:
        de_info = db.get_custom_model_info(model_id, de_name)
        fe_info = db.get_custom_model_info(model_id, fe_name)
    return ModelInfo(model_info.iloc[0], de_name, de_info, fe_name, fe_info)
