Anomaly-based Network Intrusion Detection System written in python

**Work in Progress**

---

# Installation

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required.

# Dataset preparation

## CIC-IDS-2017

[Download](http://205.174.165.80/CICDataset/CIC-IDS-2017/) the dataset and extract the file `GeneratedLabelledFlows.zip`. The default path that is assumed for the dataset is 
`data/cic-ids-2017/MachineLearningCVE`, but another path can be specified with the option `-dp` (see below). For now, only the preprocessed network flows will be used from this datasets.

# Usage

There are various subcommands:

```
❯ ./main.py --help

usage: main.py [-h] {simulate,evaluate,list-de,list-classifications} ...

positional arguments:
  {simulate,evaluate,list-de,list-classifications}
    simulate            Feed traffic from a dataset and detect anomalies.
    evaluate            Generate an evaluation report in JSON format from a
                        prediction log.
    list-de             Lists the available decision engines
    list-classifications
                        Lists all anomaly classifications that were previously
                        run.

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type `--help`, for example:

```
❯ ./main.py simulate --help

usage: main.py simulate [-h]
                        [--decision-engine {one_class_svm,local_outlier_factor}]
                        [--id ID] [--dataset-path DATASET_PATH] [--db DB]
                        [--debug]

optional arguments:
  -h, --help            show this help message and exit
  --decision-engine {one_class_svm,local_outlier_factor}
                        Choose which algorithm will be used for classifying
                        anomalies. (default: one_class_svm)
  --id ID               Id of the classification. If auto is specified, a new
                        id will be auto-generated. (default: auto)
  --dataset-path DATASET_PATH, -d DATASET_PATH
                        Path of the dataset (default: ./data/cic-
                        ids-2017/MachineLearningCVE/)
  --db DB               Database file where the classifications are stored.
                        (default: classifications.db)
  --debug, --verbose    Will produce verbose output that is useful for
                        debugging (default: False)

```

## List decision engines

The decision engine implements the algorithm to detect the anomalies. You can list available decision engines with `./main.py list-de` or:

```
❯ ./main.py list-de --short

one_class_svm
local_outlier_factor

```

## Simulate traffic, detect anomalies and create evaluation report

Read the traffic from a dataset and detect anomalies. The classifications will be written into an internal database.

```
./main.py simulate --id oc_svm_1 -d data/cic-ids-2017/MachineLearningCVE/ --decision-engine one_class_svm --kernel rbf --gamma 0.005
```

Evaluate the classification and generate a report containing different metrics:

```
./main.py evaluate --id oc_svm_1 --output evaluation.json -d data/cic-ids-2017/MachineLearningCVE/ 
```

Example content of the resulting report: 

```
❯ cat evaluation.json | head -n 32

{
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": {
        "accuracy": 0.7031695054154024,
        "balanced_accuracy": 0.7151989218719074,
        "f1_score": 0.7050652300216553,
        "false_negatives": 47933,
        "false_positives": 19075,
        "fdr": 0.19234841533140395,
        "for": 0.3786894829983567,
        "fpr": 0.1952045682474058,
        "negatives": 97718,
        "npv": 0.6213105170016433,
        "positives": 128027,
        "precision": 0.807651584668596,
        "recall": 0.6256024119912206,
        "support": 225745,
        "tnr": 0.8047954317525942,
        "true_negatives": 78643,
        "true_positives": 80094
    },
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": {
        "accuracy": 0.44455731375690744,
        "balanced_accuracy": 0.4991174702705049,
        "f1_score": 0.00248257184412458,
        "false_negatives": 158732,
        "false_positives": 384,
        "fdr": 0.6597938144329897,
        "for": 0.5552302499256694,
        "fpr": 0.0030108909571340083,
        "negatives": 127537,
        "npv": 0.44476975007433056,
        "positives": 158930,

```


