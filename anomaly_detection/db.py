import logging
import os.path
import pickle
import sqlite3
import sys
import typing as t
from contextlib import contextmanager
from multiprocessing import Lock

import pandas as pd
from numpy.core.records import ndarray

from anomaly_detection.anomaly_detector import AnomalyDetectorModel
from anomaly_detection.types import ClassificationResults, Features

SCHEMA_CHANGE_NOTES = {
    1: "",
    2: "Add total_time, packet_read_time, packet_count and is_finished columns to classification_info.",
    3: "Add is_aggregated and dataset_name columns to the evalations table."
       " Add train_set_name and dataset column to model table."
}

DB_SCHEMA_VERSION = 3

lock = Lock()


class DBConnector:
    def __init__(self, db_path: str, init_if_not_exists: bool = True,
                 schema_version=DB_SCHEMA_VERSION, migrate_if_needed=False, ):
        self.schema_version = schema_version
        self.db_path = db_path
        must_init = False
        if not os.path.exists(db_path):
            if init_if_not_exists:
                must_init = True
            else:
                raise ValueError(f"Database path '{db_path}' does not exist. Init first with the migrate command.")
        if must_init and init_if_not_exists:
            self.init_db()
        self.check_db_version(migrate_if_needed)

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
                    dataset_name TEXT,
                    train_set_name TEXT,
                    pickle_dump TEXT
                );
            """)
            c.execute(""" 
                CREATE TABLE classification_info (
                    classification_id TEXT PRIMARY KEY,
                    model_id TEXT REFERENCES model(model_id),
                    is_finished INT DEFAULT 0,
                    total_time FLOAT DEFAULT -1,
                    packet_read_time FLOAT DEFAULT -1,
                    packet_count FLOAT DEFAULT -1
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
                    dataset_name TEXT,
                    traffic_name TEXT,
                    is_aggregated INT DEFAULT 0,
                    part_name TEXT,
                    precision REAL,
                    balanced_accuracy REAL,
                    mcc REAL,
                    f1_score REAL,
                    accuracy REAL,
                    kappa REAL,
                    fdr REAL,
                    fnr REAL,
                    for REAL,
                    fpr REAL,
                    tnr REAL,
                    false_negatives INT,
                    false_positives INT,
                    true_negatives INT,
                    true_positives INT,
                    negatives INT,
                    positives INT,
                    npv REAL,
                    recall REAL,
                    support INT,
                    PRIMARY KEY (classification_id, traffic_name, part_name)
                );
            """)
            c.execute("""
                CREATE TABLE db_version (
                    version INT NOT NULL PRIMARY KEY
                );
            """)
            c.execute("""
                INSERT INTO db_version (version) values (?);
            """, (self.schema_version,))

    def check_db_version(self, migrate_if_needed):
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT version FROM db_version;", con=conn)
        if len(df["version"]) == 0:
            version = 0
        else:
            version = df["version"][0]
        if version != self.schema_version:
            logging.info("Database schema has old version %s, must migrate to %s", version, self.schema_version)
            if migrate_if_needed:
                self.migrate(old_version=version, new_version=self.schema_version)
            else:
                logging.error("Run migrate command in order to migrate database schema. Exit.")
                sys.exit(1)

    def save_model_info(self, model_id: str, decision_engine: str, transformers: t.Sequence[str],
                        feature_extractor: str, dataset_name: str, train_set_name: str, pickle_dump: str):
        with self.get_cursor() as c:
            transformer_list = ",".join(transformers)
            c.execute(
                "INSERT INTO model (model_id, decision_engine, transformers, feature_extractor, dataset_name,"
                " train_set_name, pickle_dump) VALUES (?,?,?,?,?,?,?);",
                (model_id, decision_engine, transformer_list, feature_extractor, dataset_name, train_set_name,
                 pickle_dump))

    def write_custom_model_table(self, model_id, table_name, content):
        table_cols = [
            (name, sqlite_type_of(type(value)))
            for name, value in content.items()
        ]
        # TODO check for sqlinjections in content.keys() and table name ??
        with self.get_cursor() as c:
            c.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} ( model_id TEXT PRIMARY KEY REFERENCES model(model_id), {
            ",".join(["%s %s" % (name, sql_type) for name, sql_type in table_cols])
            });
            """)
            values = [value if type(value) in [float, int, str, bool]
                      else str(value)
                      for _, value in content.items()]
            c.execute(f"""
                INSERT INTO {table_name} (model_id, {",".join([name for name, _ in table_cols])}) 
                values (?, {",".join(["?" for _ in table_cols])});
            """, [model_id] + values)

    def get_custom_model_info(self, model_id, table_name):
        if not self.exists_table(table_name):
            raise ValueError("Table %s does not exist!" % table_name)
        with self.get_conn() as conn:
            df = pd.read_sql_query(f"""
                SELECT * FROM {table_name} WHERE model_id = ?;
            """, params=(model_id,), con=conn)
        return df

    def load_model(self, model_id: str) -> AnomalyDetectorModel:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT * FROM model WHERE model_id = ?;",
                                   params=(model_id,), con=conn, index_col="model_id")
        if len(df) == 0:
            raise ValueError(f"Model with id {model_id} cannot be found in db.")

        pickle_str = df["pickle_dump"][0]
        model = AnomalyDetectorModel.deserialize(pickle_str)
        return model

    def new_classification_info(self, classification_id, model_id):
        with self.get_cursor() as c:
            c.execute("INSERT INTO classification_info (classification_id, model_id, is_finished) VALUES (?,?,0);",
                      (classification_id, model_id))

    def save_classifications(self, r: ClassificationResults):
        with self.get_cursor() as c:
            data = [(r.classification_id, i, p.value)
                    for i, p in zip(r.traffic_ids, r.predictions)]
            c.executemany("INSERT INTO classification_results (classification_id, record_id, label) VALUES (?,?,?);",
                          data)

    def finish_classification(self, classification_id: str, total_time: float, read_time: float, packet_count: int):
        with self.get_cursor() as c:
            c.execute("""
                UPDATE classification_info SET is_finished = 1, packet_read_time = ?, total_time = ?, packet_count = ?
                WHERE classification_id = ?;
            """, (read_time, total_time, packet_count, classification_id))

    def get_classifications_records(self, classification_id: str) -> pd.DataFrame:
        with self.get_conn() as conn:
            df = pd.read_sql_query("SELECT record_id, label FROM classification_results WHERE classification_id = ?",
                                   params=(
                                       classification_id,), con=conn, index_col="record_id")
        return df

    def get_model_infos(self) -> pd.DataFrame:
        with self.get_conn() as conn:
            df = pd.read_sql_query(
                "SELECT model_id, feature_extractor, transformers, decision_engine, dataset_name, test_set_name FROM model;",
                con=conn, index_col="model_id")
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

    def store_evaluation(self, classification_id, traffic_name, part_name, is_aggregated, dataset_name, metrics):
        with self.get_cursor() as c:
            c.execute("""
            INSERT INTO evaluations (classification_id, dataset_name, traffic_name, part_name, is_aggregated,
                accuracy, balanced_accuracy, f1_score, false_negatives, false_positives, fdr, fnr, for, fpr,
                negatives, positives, npv, precision, recall, support, tnr, true_negatives, true_positives, mcc, kappa)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);
                """,
                      (
                          classification_id, dataset_name, traffic_name, part_name, is_aggregated, metrics["accuracy"],
                          metrics["balanced_accuracy"],
                          metrics["f1_score"],
                          metrics["false_negatives"], metrics["false_positives"], metrics["fdr"], metrics["fnr"],
                          metrics["for"],
                          metrics["fpr"], metrics["negatives"], metrics["positives"], metrics["npv"],
                          metrics["precision"],
                          metrics["recall"], metrics["support"], metrics["tnr"], metrics["true_negatives"],
                          metrics["true_positives"], metrics["mcc"], metrics["kappa"]))

    def get_evaluations(self):
        with self.get_conn() as conn:
            df = pd.read_sql_query(
                "SELECT m.model_id, m.decision_engine, m.feature_extractor, m.transformers, e.* FROM model m "
                "JOIN classification_info c ON m.model_id = c.model_id JOIN evaluations e ON e.classification_id = c.classification_id;",
                con=conn)
        return df

    def get_evaluations_by_model_param(self, model_part_table_name: str, part_name: str = "all"):
        if not self.exists_table(model_part_table_name):
            raise ValueError("Table %s does not exist!" % model_part_table_name)
        with self.get_conn() as c:
            df = pd.read_sql_query(f"""
            SELECT p.*, e.*
            FROM "{model_part_table_name}" p JOIN classification_info c ON p.model_id = c.model_id 
            JOIN evaluations e ON e.classification_id = c.classification_id WHERE e.part_name = ?""",
                                   con=c, params=(part_name,))
        return df

    def migrate(self, old_version, new_version):
        migrated = False
        with self.get_cursor() as c:
            if new_version >= 2 and old_version < 2:
                c.execute("ALTER TABLE classification_info ADD COLUMN is_finished INT DEFAULT -1;")
                c.execute("ALTER TABLE classification_info  ADD COLUMN packet_count INT DEFAULT -1;")
                c.execute("ALTER TABLE classification_info  ADD COLUMN packet_read_time FLOAT DEFAULT -1;")
                c.execute("ALTER TABLE classification_info  ADD COLUMN total_time FLOAT DEFAULT -1;")
                migrated = True
            if new_version >= 3 and old_version < 3:
                c.execute("ALTER TABLE evaluations ADD COLUMN is_aggregated INT DEFAULT 0;")
                c.execute("ALTER TABLE evaluations ADD COLUMN dataset_name TEXT;")
                c.execute("ALTER TABLE model ADD COLUMN train_set_name;")
                c.execute("ALTER TABLE model ADD COLUMN dataset_name;")
                migrated = True
        if migrated == False:
            raise ValueError("Cannot migrate from database schema version %s to %s" % (old_version, new_version))
        # only executed if above migrations where successful
        with self.get_cursor() as c:
            c.execute("UPDATE db_version SET version = ?;", (new_version,))
        logging.info("Migrated from database schema version %s to %s" % (old_version, new_version))

    def exists_table(self, name):
        with self.get_conn() as conn:
            query = "SELECT 1 FROM sqlite_master WHERE type='table' and name = ?"
            return conn.execute(query, (name,)).fetchone() is not None


def sqlite_type_of(python_type) -> str:
    if python_type is int or python_type is bool:
        return "INT"
    if python_type is float:
        return "REAL"
    return "TEXT"
