import sqlite3
import pandas as pd
import os.path


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
            CREATE TABLE simulation_info (
                classification_id TEXT REFERENCES classification_info(classification_id) PRIMARY KEY,
                dataset_id TEXT
            );
        """)
        self.conn.commit()

    def save_model_info(self, model_id, decision_engine, pickle_dump):
        c = self.conn.cursor()
        c.execute("INSERT INTO model (model_id, decision_engine, pickle_dump) VALUES (?,?,?);",
                  (model_id, decision_engine, pickle_dump))
        self.conn.commit()
        c.close()

    def save_classification_info(self, classification_id, model_id):
        c = self.conn.cursor()
        c.execute("INSERT INTO classification_info (classification_id, model_id) VALUES (?,?);",
                  (classification_id, model_id))
        self.conn.commit()
        c.close()

    def save_classifications(self, classification_id, record_ids: list, labels: list):
        c = self.conn.cursor()
        data = [(classification_id, i, p.value)
                for i, p in zip(record_ids, labels)]
        c.executemany("INSERT INTO classification_results (classification_id, record_id, label) VALUES (?,?,?);",
                      data)
        self.conn.commit()
        c.close()

    def get_classifications_records(self, classification_id: str) -> pd.DataFrame:
        df = pd.read_sql_query("SELECT record_id, label FROM classification_results WHERE classification_id = ?", params=(
            classification_id,), con=self.conn, index_col="record_id")
        return df

    def get_classification_info(self) -> pd.DataFrame:
        df = pd.read_sql_query(
            "SELECT classification_id, model_id FROM classification_info", con=self.conn)
        return df

    def exists_classification(self, classification_id: str) -> bool:
        df = pd.read_sql_query(
            "SELECT * FROM classification_info WHERE classification_id = ?",
            params=(classification_id,), con=self.conn)
        return len(df) > 0 
