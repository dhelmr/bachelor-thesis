import datetime
import logging
import os

import pandas
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from canids.db import DBConnector
from canids.evaluation_retriever import EvaluationRetriever, HyperparamGrouping
from canids.model_info import get_info


class EvaluationsVisualizer:
    def __init__(self, db: DBConnector, output_dir: str, detailed_info: bool = True):
        self.db = db
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        self.model_infos = db.get_model_infos()
        self.detailed_info = detailed_info

    def visualize(self, model_part_name: str):
        retriever = EvaluationRetriever(self.db, model_part_name)
        filename = f"{model_part_name}_{datetime.datetime.now().isoformat()}.html"
        path = os.path.join(self.output_dir, filename)

        hyperparam_groupings = retriever.group_for_all()
        figures = [
            self._make_plot(model_part_name, grouping)
            for grouping in hyperparam_groupings.values()
        ]
        with open(path, "w") as f:
            f.write("<html><head><title>%s</title></head><body>" % model_part_name)
            for fig in figures:
                f.write(fig.to_html(full_html="false", include_plotlyjs="cdn"))
                f.write("<hr>")
            f.write("</body></html>")

    def _make_plot(self, model_part_name: str, grouping: HyperparamGrouping):
        fig = make_subplots(
            rows=2,
            cols=2,
            vertical_spacing=0.2,
            horizontal_spacing=0.05,
            x_title=grouping.variable_hyperparam,
            subplot_titles=("precision", "mcc", "f1_score", "recall"),
        )
        fig["layout"]["margin"] = {"l": 30, "r": 10, "b": 50, "t": 25}
        color_selector = ColorSelector(
            colors=px.colors.qualitative.Plotly
            + px.colors.qualitative.Bold
            + px.colors.qualitative.D3
        )
        unique_test_splits = grouping.unique_values("traffic_name")
        legend_items = set()
        for fixed_params, evaluations in grouping.as_tuples():
            color_key = (
                fixed_params["dataset_name"],
                fixed_params["traffic_name"],
                fixed_params["part_name"],
            )
            color = color_selector.get(color_key)
            if len(unique_test_splits) > 1:
                name = f"%s/%s - %s" % (
                    fixed_params["dataset_name"],
                    fixed_params["traffic_name"],
                    fixed_params["part_name"],
                )
            else:
                name = f"%s - %s" % (
                    fixed_params["dataset_name"],
                    fixed_params["part_name"],
                )
            if name not in legend_items:
                legend_items.add(name)
                new_legend_item = True
            else:
                new_legend_item = False
            self._add_trace(
                fig,
                evaluations,
                x=grouping.variable_hyperparam,
                y="precision",
                part_name=fixed_params["part_name"],
                row=1,
                col=1,
                color=color,
                name=name,
                init_group=new_legend_item,
            )
            self._add_trace(
                fig,
                evaluations,
                x=grouping.variable_hyperparam,
                y="mcc",
                part_name=fixed_params["part_name"],
                color=color,
                name=name,
                row=1,
                col=2,
            )
            self._add_trace(
                fig,
                evaluations,
                x=grouping.variable_hyperparam,
                y="f1_score",
                part_name=fixed_params["part_name"],
                color=color,
                name=name,
                row=2,
                col=1,
            )
            self._add_trace(
                fig,
                evaluations,
                x=grouping.variable_hyperparam,
                y="recall",
                part_name=fixed_params["part_name"],
                color=color,
                name=name,
                row=2,
                col=2,
            )
        layout = go.Layout(yaxis=dict(range=[0, 1]))
        fig.update_layout(layout)
        return fig

    def _add_trace(
        self, fig, evaluations, x, y, part_name, row, col, color, name, init_group=False
    ):
        df = pandas.DataFrame(evaluations)
        fig.add_trace(
            go.Scatter(
                x=df[x],
                y=df[y],
                legendgroup=name,
                showlegend=init_group,
                mode="lines+markers",
                marker_color=color,
                line=dict(color=color),
                name=name,
                hovertemplate=df.apply(
                    lambda row: self._make_hover_value(row, x, y), axis=1
                ),
            ),
            row=row,
            col=col,
        )

    def _make_hover_value(self, row, hyperparam, metric):
        row_info = str(row.T).replace("\n", "<br>")
        try:
            model_info = (
                get_info(
                    self.db,
                    model_id=row["model_id"],
                    model_infos=self.model_infos,
                    detailed_info=self.detailed_info,
                )
                .pretty()
                .replace("\n", "<br>")
            )
        except ValueError as e:
            logging.warning("Cannot find model %s", row["model_id"], exc_info=e)
            model_info = "Cannot find model info"
        row_info = row.T.__str__().replace("\n", "<br>")
        return (
            "<b>%s=%s %s=%s </b> <br>" % (hyperparam, "%{x}", metric, "%{y:.0%}")
            + f"""
        <hr>
        {model_info} <br>
        <hr>
        {row_info}
        """
        )


class ColorSelector:
    def __init__(self, colors):
        self._color_assortment = colors
        self._color_mapping = {}
        self._next_index = 0

    def get(self, key):
        if key not in self._color_mapping:
            self._color_mapping[key] = self._color_assortment[self._next_index]
            self._next_index = (self._next_index + 1) % len(self._color_assortment)
        return self._color_mapping[key]
