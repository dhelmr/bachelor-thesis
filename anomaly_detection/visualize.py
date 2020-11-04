import datetime
import logging
import os

import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from anomaly_detection.db import DBConnector
from anomaly_detection.model_info import get_info


class EvaluationsVisualizer:
    def __init__(self, db: DBConnector, output_dir: str, detailed_info: bool = True):
        self.db = db
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        self.model_infos = db.get_model_infos()
        self.detailed_info = detailed_info

    def visualize(self, model_part_name: str, hyperparam=None):
        df, hyperparams = self.db.get_evaluations_by_model_param(model_part_name)
        if hyperparam is not None and hyperparam not in hyperparams:
            raise ValueError("No hyperparameter called %s found in %s!" % (hyperparam, model_part_name))
        if hyperparam is not None:
            hyperparams = [hyperparam]

        filename = f"{model_part_name}_{datetime.datetime.now().isoformat()}.html"
        path = os.path.join(self.output_dir, filename)

        figures = [self._make_plot(model_part_name, df, hp) for hp in hyperparams]
        with open(path, "w") as f:
            f.write("<html><head><title>%s</title></head><body>" % model_part_name)
            for fig in figures:
                f.write(fig.to_html(full_html="false", include_plotlyjs="cdn"))
                f.write("<hr>")
            f.write("</body></html>")

    def _make_plot(self, model_part_name: str, df, hyperparam):
        fig = make_subplots(rows=2, cols=2, vertical_spacing=0.2, horizontal_spacing=0.05,
                            x_title=hyperparam,
                            subplot_titles=("precision", "mcc", "f1_score", "recall")
                            )
        fig['layout']['margin'] = {'l': 30, 'r': 10, 'b': 50, 't': 25}

        colors = px.colors.qualitative.Plotly + px.colors.qualitative.Bold + px.colors.qualitative.D3
        color_index = 0
        for part_name in df["part_name"].unique():
            by_part_names = df[df["part_name"] == part_name]
            for dataset in by_part_names["dataset_name"].unique():
                color_index += 1
                f = by_part_names[by_part_names["dataset_name"] == dataset]
                color = colors[color_index % len(colors)]
                name = f"{part_name} ({dataset})"
                self._add_trace(fig, f, x=hyperparam, y="precision", part_name=part_name, row=1, col=1, color=color,
                                name=name, init_group=True)
                self._add_trace(fig, f, x=hyperparam, y="mcc", part_name=part_name, color=color, name=name, row=1,
                                col=2)
                self._add_trace(fig, f, x=hyperparam, y="f1_score", part_name=part_name, color=color, name=name, row=2,
                                col=1)
                self._add_trace(fig, f, x=hyperparam, y="recall", part_name=part_name, color=color, name=name, row=2,
                                col=2)

        layout = go.Layout(yaxis=dict(range=[0, 1]))
        fig.update_layout(layout)
        return fig

    def _add_trace(self, fig, df, x, y, part_name, row, col, color, name, init_group=False):
        fig.add_trace(go.Scatter(x=df[x], y=df[y], legendgroup=name, showlegend=init_group, mode="markers",
                                 marker=dict(color=color), name=name,
                                 hovertemplate=df.apply(lambda row: self._make_hover_value(row, x, y), axis=1)),
                      row=row, col=col)

    def _make_hover_value(self, row, hyperparam, metric):
        row_info = str(row.T).replace('\n', "<br>")
        try:
            model_info = get_info(self.db,
                                  model_id=row["model_id"],
                                  model_infos=self.model_infos,
                                  detailed_info=self.detailed_info
                                  ).pretty().replace("\n", "<br>")
        except ValueError as e:
            logging.warning("Cannot find model %s", row["model_id"], exc_info=e)
            model_info = "Cannot find model info"
        row_info = row.T.__str__().replace("\n", "<br>")
        return "<b>%s=%s %s=%s </b> <br>" % (hyperparam, "%{x}", metric, "%{y:.0%}") + \
               f"""
        <hr>
        {model_info} <br>
        <hr>
        {row_info}
        """
