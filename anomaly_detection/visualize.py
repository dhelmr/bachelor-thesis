import matplotlib.pyplot as plt

from anomaly_detection.db import DBConnector


class EvaluationsVisualizer:
    def __init__(self, db: DBConnector):
        self.db = db

    def visualize(self, model_part_name: str, hyperparam: str, part_name: str = "all"):
        df = self.db.get_evaluations_by_model_param(model_part_name, part_name)
        if hyperparam not in df.columns:
            raise ValueError("No hyperparameter called %s found in %s!" % (hyperparam, model_part_name))
        print(df)
        X = df[hyperparam].values.tolist()
        Y = df["precision"].values.tolist()
        fig = plt.figure()
        #  ax = fig.add_axes([0, 0, 1, 1])
        plt.scatter(X, Y, color="b")
        plt.show()
