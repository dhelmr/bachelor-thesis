import os.path
import pickle
import sqlite3
import typing as t

import pandas as pd
from numpy.core.records import ndarray

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.types import ClassificationResults


class DBConnector:
    def __init__(self, db_path: str, init_if_not_exists: bool = True):
        must_init = False
        if not os.path.exists(db_path):
            if init_if_not_exists:
                must_init = True
            else:
                raise ValueError(f"Database path '{db_path}' does not exist.")
        self.conn = sqlite3.connect(db_path)
        if must_init and init_if_not_exists:
            self.init_db()

    def init_db(self):
        c = self.conn.cursor()
        c.execute(""" 
            CREATE TABLE classification_results (
                classification_id TEXT REFERENCES classification_info(classification_id),
                record_id TEXT NOT NULL, 
                label INTEGER NOT NULL,
                PRIMARY KEY (classification_id, record_id)
            );
        """)
        c.execute(""" 
            CREATE TABLE model (
                model_id TEXT PRIMARY KEY,
                decision_engine TEXT,
                transformers TEXT,
                feature_extractor TEXT,
                pickle_dump TEXT
            );
        """)
        c.execute(""" 
            CREATE TABLE classification_info (
                classification_id TEXT PRIMARY KEY,
                model_id TEXT REFERENCES model(model_id)
            );
        """)
        c.execute("""
            CREATE TABLE extracted_features (
                fe_id TEXT,
                traffic_name TEXT,
                pickle_features TEXT,
                model_id REFERENCES model(model_id),
                PRIMARY KEY (fe_id, traffic_name)
            );
        """)
        self.conn.commit()

    def save_model_info(self, model_id: str, decision_engine: str, transformers: t.Sequence[str],
                        feature_extractor: str, pickle_dump: str):
        c = self.conn.cursor()
        transformer_list = ",".join(transformers)
        c.execute(
            "INSERT INTO model (model_id, decision_engine, transformers, feature_extractor, pickle_dump) VALUES (?,?,?,?,?);",
            (model_id, decision_engine, transformer_list, feature_extractor, pickle_dump))
        self.conn.commit()
        c.close()

    def load_model(self, model_id: str) -> AnomalyDetectorModel:
        df = pd.read_sql_query("SELECT * FROM model WHERE model_id = ?;",
                               params=(model_id,), con=self.conn, index_col="model_id")
        if len(df) == 0:
            raise ValueError(f"Model with id {model_id} cannot be found in db.")

        pickle_str = df["pickle_dump"][0]
        model = AnomalyDetectorModel.deserialize(pickle_str)
        return model

    def save_classification_info(self, classification_id, model_id):
        c = self.conn.cursor()
        c.execute("INSERT INTO classification_info (classification_id, model_id) VALUES (?,?);",
                  (classification_id, model_id))
        self.conn.commit()
        c.close()

    def save_classifications(self, r: ClassificationResults):
        c = self.conn.cursor()
        data = [(r.classification_id, i, p.value)
                for i, p in zip(r.traffic_ids, r.predictions)]
        c.executemany("INSERT INTO classification_results (classification_id, record_id, label) VALUES (?,?,?);",
                      data)
        self.conn.commit()
        c.close()

    def get_classifications_records(self, classification_id: str) -> pd.DataFrame:
        df = pd.read_sql_query("SELECT record_id, label FROM classification_results WHERE classification_id = ?",
                               params=(
                                   classification_id,), con=self.conn, index_col="record_id")
        return df

    def get_all_models(self) -> pd.DataFrame:
        df = pd.read_sql_query("SELECT * FROM model;", con=self.conn, index_col="model_id")
        return df

    def get_all_classifications(self, with_count=False) -> pd.DataFrame:
        sql = "SELECT classification_id, model_id FROM classification_info;"
        if with_count:
            sql = """
             SELECT classification_info.classification_id, classification_info.model_id, COUNT(classification_results.record_id) as records
             FROM classification_info LEFT JOIN classification_results
             ON classification_info.classification_id = classification_results.classification_id
             GROUP BY classification_info.classification_id;
             """
        df = pd.read_sql_query(
            sql, con=self.conn, index_col="classification_id")
        return df

    def exists_classification(self, classification_id: str) -> bool:
        df = pd.read_sql_query(
            "SELECT * FROM classification_info WHERE classification_id = ?",
            params=(classification_id,), con=self.conn)
        return len(df) > 0

    def exists_model(self, model_id: str) -> bool:
        df = pd.read_sql_query("SELECT model_id FROM model WHERE model_id = ?;", con=self.conn, params=(model_id,))
        return len(df) > 0

    def exist_features(self, fe_id: str, traffic_name: str):
        df = pd.read_sql_query("SELECT fe_id FROM extracted_features "
                               "WHERE fe_id = ? and traffic_name=?;", con=self.conn, params=(fe_id, traffic_name))
        return len(df) > 0

    def load_features(self, fe_id, traffic_name) -> ndarray:
        df = pd.read_sql_query("SELECT pickle_features FROM extracted_features "
                               "WHERE fe_id = ? and traffic_name=?;", con=self.conn, params=(fe_id, traffic_name))
        if len(df) == 0:
            raise ValueError("Features for %s and %s do not exist in db!" % (fe_id, traffic_name))
        obj = pickle.loads(df["pickle_features"][0])
        if type(obj) is not ndarray:
            raise ValueError("Stored features in database have wrong type! Found %s" % type(obj))
        return obj

    def load_model_by_fe_id(self, fe_id, traffic_name):
        df = pd.read_sql_query("SELECT model_id FROM extracted_features "
                               "WHERE fe_id = ? and traffic_name=?;", con=self.conn, params=(fe_id, traffic_name))
        if len(df) == 0:
            raise ValueError("Features for %s and %s do not exist in db!" % (fe_id, traffic_name))
        return self.load_model(df["model_id"][0])

    def store_features(self, fe_id, traffic_name, features: ndarray, model_id: str):
        pickle_dump = pickle.dumps(features)
        c = self.conn.cursor()
        c.execute("INSERT INTO extracted_features (fe_id, traffic_name, pickle_features, model_id) VALUES (?,?,?,?);",
                  (fe_id, traffic_name, pickle_dump, model_id))
        self.conn.commit()
        c.close()
