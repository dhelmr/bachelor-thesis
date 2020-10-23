import os.path
import pickle
import sqlite3
import typing as t
from contextlib import contextmanager
from multiprocessing import Lock

import pandas as pd
from numpy.core.records import ndarray

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.types import ClassificationResults, Features

lock = Lock()

class DBConnector:
    def __init__(self, db_path: str, init_if_not_exists: bool = True):
        self.db_path = db_path
        must_init = False
        if not os.path.exists(db_path):
            if init_if_not_exists:
                must_init = True
            else:
                raise ValueError(f"Database path '{db_path}' does not exist.")
        if must_init and init_if_not_exists:
            self.init_db()


    @contextmanager
    def get_conn(self):
        global lock
        lock.acquire()
        try:
            conn = sqlite3.connect(self.db_path, timeout=999)
            yield conn
        except:
            conn.close()
            lock.release()
            raise
        else:
            conn.close()
            lock.release()

    @contextmanager
    def get_cursor(self):
        with self.get_conn() as conn:
            try:
                c = conn.cursor()
                yield c
            except:
                conn.rollback()
                c.close()
                raise
            else:
                conn.commit()
                c.close()

    def init_db(self):
        with self.get_cursor() as c:
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
            c.execute("""
                CREATE TABLE evaluations (
                    classification_id TEXT REFERENCES classification_info(classification_id),
                    part_name TEXT,
                    traffic_name TEXT,
                    accuracy REAL,
                    balanced_accuracy REAL,
                    f1_score REAL,
                    false_negatives INT,
                    false_positives INT,
                    fdr REAL,
                    fnr REAL,
                    for REAL,
                    fpr REAL,
                    negatives INT,
                    positives INT,
                    npv REAL,
                    precision REAL,
                    recall REAL,
                    support INT,
                    tnr REAL,
                    true_negatives INT,
                    true_positives INT,
                    PRIMARY KEY (classification_id, traffic_name, part_name)
                );
            """)

    def save_model_info(self, model_id: str, decision_engine: str, transformers: t.Sequence[str],
                        feature_extractor: str, pickle_dump: str):
        with self.get_cursor() as c:
            transformer_list = ",".join(transformers)
            c.execute(
                "INSERT INTO model (model_id, decision_engine, transformers, feature_extractor, pickle_dump) VALUES (?,?,?,?,?);",
                (model_id, decision_engine, transformer_list, feature_extractor, pickle_dump))

    def load_model(self, model_id: str) -> AnomalyDetectorModel:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT * FROM model WHERE model_id = ?;",
                                   params=(model_id,), con=conn, index_col="model_id")
        if len(df) == 0:
            raise ValueError(f"Model with id {model_id} cannot be found in db.")

        pickle_str = df["pickle_dump"][0]
        model = AnomalyDetectorModel.deserialize(pickle_str)
        return model

    def save_classification_info(self, classification_id, model_id):
        with self.get_cursor() as c:
            c.execute("INSERT INTO classification_info (classification_id, model_id) VALUES (?,?);",
                      (classification_id, model_id))

    def save_classifications(self, r: ClassificationResults):
        with self.get_cursor() as c:
            data = [(r.classification_id, i, p.value)
                    for i, p in zip(r.traffic_ids, r.predictions)]
            c.executemany("INSERT INTO classification_results (classification_id, record_id, label) VALUES (?,?,?);",
                          data)

    def get_classifications_records(self, classification_id: str) -> pd.DataFrame:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT record_id, label FROM classification_results WHERE classification_id = ?",
                                   params=(
                                       classification_id,), con=conn, index_col="record_id")
        return df

    def get_all_models(self) -> pd.DataFrame:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT * FROM model;", con=conn, index_col="model_id")
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
        with self.get_conn() as conn:
            df = pd.read_sql_query(
                sql, con=conn, index_col="classification_id")
        return df

    def exists_classification(self, classification_id: str) -> bool:
        with self.get_conn() as conn:
            df = pd.read_sql_query(
                "SELECT * FROM classification_info WHERE classification_id = ?",
                params=(classification_id,), con=conn)
        return len(df) > 0

    def exists_model(self, model_id: str, try_count: int = 0) -> bool:
        try:
            with self.get_conn() as conn:
                df = pd.read_sql_query("SELECT model_id FROM model WHERE model_id = ?;", con=conn, params=(model_id,))
            return len(df) > 0
        except sqlite3.OperationalError as e:
            if try_count > 3:
                raise e
            else:
                # Due to some bug, the database is sometimes still locked
                return self.exists_model(model_id, try_count=try_count + 1)

    def exist_features(self, fe_id: str, traffic_name: str):
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT fe_id FROM extracted_features "
                                   "WHERE fe_id = ? and traffic_name=?;", con=conn, params=(fe_id, traffic_name))
        return len(df) > 0

    def load_features(self, fe_id, traffic_name) -> ndarray:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT pickle_features FROM extracted_features "
                                   "WHERE fe_id = ? and traffic_name=?;", con=conn, params=(fe_id, traffic_name))
        if len(df) == 0:
            raise ValueError("Features for %s and %s do not exist in db!" % (fe_id, traffic_name))
        obj = pickle.loads(df["pickle_features"][0])
        if type(obj) is not Features:
            raise ValueError("Stored features in database have wrong type! Found %s" % type(obj))
        return obj

    def load_model_by_fe_id(self, fe_id, traffic_name):
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT model_id FROM extracted_features "
                                   "WHERE fe_id = ? and traffic_name=?;", con=conn, params=(fe_id, traffic_name))
        if len(df) == 0:
            raise ValueError("Features for %s and %s do not exist in db!" % (fe_id, traffic_name))
        return self.load_model(df["model_id"][0])

    def store_features(self, fe_id, traffic_name, features: ndarray, model_id: str):
        pickle_dump = pickle.dumps(features)
        with self.get_cursor() as c:
            c.execute(
                "INSERT INTO extracted_features (fe_id, traffic_name, pickle_features, model_id) VALUES (?,?,?,?);",
                (fe_id, traffic_name, pickle_dump, model_id))

    def store_evaluation(self, classification_id, traffic_name, part_name, metrics):
        with self.get_cursor() as c:
            c.execute(
                "INSERT INTO evaluations (classification_id, part_name, traffic_name, accuracy, balanced_accuracy, f1_score, false_negatives, false_positives, fdr, fnr, for, fpr, negatives, positives, npv, precision, recall, support, tnr, true_negatives, true_positives) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
                (
                    classification_id, part_name, traffic_name, metrics["accuracy"], metrics["balanced_accuracy"],
                    metrics["f1_score"],
                    metrics["false_negatives"], metrics["false_positives"], metrics["fdr"], metrics["fnr"],
                    metrics["for"],
                    metrics["fpr"], metrics["negatives"], metrics["positives"], metrics["npv"], metrics["precision"],
                    metrics["recall"], metrics["support"], metrics["tnr"], metrics["true_negatives"],
                    metrics["true_positives"]))
