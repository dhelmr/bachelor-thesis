import datetime
import enum
import logging
import math
import os
from typing import Tuple

import pandas
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from canids.db import DBConnector
from canids.evaluation_retriever import EvaluationGrouper, HyperparamGrouping
from canids.model_info import get_info


class VisualizationMode(enum.Enum):
    METRICS = "metrics"
    FDR_ROC = "fdr_roc"


class EvaluationsVisualizer:
    def __init__(
        self,
        db: DBConnector,
        mode: VisualizationMode,
        output_dir: str,
        detailed_info: bool = True,
    ):
        self.db = db
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        self.model_infos = db.get_model_infos()
        self.detailed_info = detailed_info
        self.mode = mode

    def visualize(self, model_part_name: str):
        retriever = EvaluationGrouper(self.db, model_part_name)

        # TODO this should be loaded dynamically from the decision engine class
        if model_part_name == "autoencoder":
            # threshold is not a hyperparameter, but a variable that is determined by the model during training
            retriever.ignore_hyperparams.append("threshold")
            retriever.ignore_hyperparams.append("layer_sizes")

        make_plot = {
            VisualizationMode.METRICS: self._make_metrics_plot,
            VisualizationMode.FDR_ROC: self._make_roc_plot,
        }[self.mode]

        hyperparam_groupings = retriever.group_for_all()
        figures = [
            (param_name, make_plot(model_part_name, grouping))
            for param_name, grouping in hyperparam_groupings.items()
        ]

        timestamp = datetime.datetime.now().isoformat()
        for param_name, fig in figures:
            filename = (
                f"{model_part_name}_{self.mode.value}_{timestamp}_{param_name}.html"
            )
            path = os.path.join(self.output_dir, filename)
            with open(path, "w") as f:
                f.write(fig.to_html(include_plotlyjs="cdn"))

    def _make_roc_plot(self, model_part_name: str, grouping: HyperparamGrouping):
        evaluations_by_attacks = {}
        for fixed_params, evaluations in grouping.as_tuples():
            attack_category = (
                fixed_params["dataset_name"],
                fixed_params["traffic_name"],
                fixed_params["part_name"],
            )
            if attack_category not in evaluations_by_attacks:
                evaluations_by_attacks[attack_category] = []
            evaluations_by_attacks[attack_category].append((fixed_params, evaluations))

        roc_points = {}
        for attack_category, evaluations in evaluations_by_attacks.items():
            roc_points[attack_category] = []
            for fixed_params, evaluation in evaluations:
                X, Y, variable_param_vals = [], [], []
                for run in evaluation:
                    fdr = run["fdr"]
                    tpr = run["recall"]
                    X.append(fdr)
                    Y.append(tpr)
                    variable_param_vals.append(run[grouping.variable_hyperparam])
                roc_points[attack_category].append(
                    (fixed_params, X, Y, variable_param_vals)
                )

        attacks = list(map(str, roc_points.keys()))
        cols = min(5, len(attacks))
        rows = math.ceil(len(attacks) / 5)
        fig = make_subplots(
            cols=cols,
            rows=rows,
            x_title=grouping.variable_hyperparam,
            subplot_titles=attacks,
        )
        grid_counter = GridCounter(cols=cols, rows=rows)
        color_selector = ColorSelector(
            colors=px.colors.qualitative.Plotly
            + px.colors.qualitative.Bold
            + px.colors.qualitative.D3
        )
        for attack_category, roc in roc_points.items():
            col, row = grid_counter.get()
            for fixed_params, X, Y, variable_param_values in roc:
                # name = f"{grouping.variable_hyperparam}={variable_param_value}"
                name = self._make_name_from_fixed_params(fixed_params)
                init_group = not color_selector.has(name)
                color = color_selector.get(name)
                hovertexts = [
                    f"rc={Y[i]}; fdr={X[i]}; {grouping.variable_hyperparam}={variable_param_values[i]}"
                    for i in range(len(X))
                ]
                fig.add_trace(
                    go.Scatter(
                        x=X,
                        y=Y,
                        legendgroup=name,
                        showlegend=init_group,
                        mode="lines+markers",
                        marker_color=color,
                        line=dict(color=color),
                        name=name,
                        hovertext=hovertexts,
                    ),
                    row=row,
                    col=col,
                )
            grid_counter.next()
        fig.update_xaxes(range=[-0.1, 1.1])
        fig.update_yaxes(range=[-0.1, 1.1])
        return fig

    def _make_name_from_fixed_params(self, fixed_params):
        model_params = {
            key: value
            for key, value in fixed_params.items()
            if key not in {"dataset_name", "traffic_name", "part_name"}
        }
        return "; ".join([f"{key}={value}" for key, value in model_params.items()])

    def _make_metrics_plot(self, model_part_name: str, grouping: HyperparamGrouping):
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

    def has(self, key):
        return key in self._color_mapping


class GridCounter(object):
    def __init__(self, cols: int, rows: int):
        self.rows = rows
        self.cols = cols
        self._curX = 1
        self._curY = 1

    def get(self) -> Tuple[int, int]:
        return self._curX, self._curY

    def next(self) -> Tuple[int, int]:
        self._curX += 1
        if self._curX > self.cols:
            self._curY += 1
            self._curX = 1
        return self.get()
