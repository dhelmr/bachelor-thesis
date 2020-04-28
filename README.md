Anomaly-based Network Intrusion Detection System written in python

**Work in Progress**

---

# Dataset preparation

## CIC-IDS-2017

[Download](http://205.174.165.80/CICDataset/CIC-IDS-2017/) the dataset and extract the file `GeneratedLabelledFlows.zip`. The default path that is assumed for the dataset is 
`data/cic-ids-2017/MachineLearningCVE`, but another path can be specified with the option `-dp` (see below). For now, only the preprocessed network flows will be used from this datasets.

# Usage

Clone the git repo, install the requirements with `pip install -r requirements.txt` and then execute `main.py`:

```
❯ ./main.py --help

usage: main.py [-h] {simulate,evaluate,list-de} ...

positional arguments:
  {simulate,evaluate,list-de}
    simulate            Feed traffic from a dataset and detect anomalies.
    evaluate            Generate an evaluation report in JSON format from a
                        prediction log.
    list-de             Lists the available decision engines

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type, for example:

```
❯ ./main.py simulate --help

usage: main.py simulate [-h] [--logfile LOGFILE]
                        [--decision-engine {one_class_svm,local_outlier_factor}]
                        [--dataset-path DATASET_PATH]

optional arguments:
  -h, --help            show this help message and exit
  --logfile LOGFILE, -l LOGFILE
                        Log file where the predictions will be written into
                        (default: log-2020-04-28 17:26:39.227945.csv)
  --decision-engine {one_class_svm,local_outlier_factor}
                        Choose which algorithm will be used for classifying
                        anomalies. (default: one_class_svm)
  --dataset-path DATASET_PATH, -d DATASET_PATH
                        Path of the dataset (default: ./data/cic-
                        ids-2017/MachineLearningCVE/)

```

Currently, there is only one decision engine implemented: OneClassSVM. It is selected by default. You can list all available engines and their parameters with:

```
❯ ./main.py list-de


>>> one_class_svm <<<

usage: one_class_svm [-h] [--gamma GAMMA] [--nu NU]
                     [--kernel {rbf,polynomial,linear,sigmoid}]
                     [--tolerance TOLERANCE] [--coef0 COEF0]
                     [--max-iter MAX_ITER] [--shrinking SHRINKING]
                     [--degree DEGREE] [--cache-size CACHE_SIZE]

optional arguments:
  -h, --help            show this help message and exit
  --gamma GAMMA         Kernel coefficient for ‘rbf’, ‘poly’ and ‘sigmoid’
                        kernels (default: 0.005)
  --nu NU               An upper bound on the fraction of training errors and
                        a lower bound of the fraction of support vectors.
                        Should be in the interval (0, 1]. (default: 0.001)
  --kernel {rbf,polynomial,linear,sigmoid}
  --tolerance TOLERANCE
                        Tolerance for stopping criterion. (default: 0.001)
  --coef0 COEF0         Independent term in kernel function. It is only
                        significant in ‘poly’ and ‘sigmoid’ (default: 0.0)
  --max-iter MAX_ITER   Hard limit on iterations within solver, or -1 for no
                        limit. (default: -1)
  --shrinking SHRINKING
                        Whether to use the shrinking heuristic. (default:
                        True)
  --degree DEGREE       Degree of the polynomial kernel function (‘poly’).
                        Ignored by all other kernels. (default: 3)
  --cache-size CACHE_SIZE
                        Specify the size of the kernel cache (in MB).
                        (default: 500.0)

>>> local_outlier_factor <<<

usage: local_outlier_factor [-h]

optional arguments:
  -h, --help  show this help message and exit

```

## Simulate traffic, detect anomalies and create evaluation report

Read the traffic from a dataset and detect anomalies. The classifications will be written into a csv file:

```
./main.py simulate --logfile classification-log.csv -d data/cic-ids-2017/MachineLearningCVE/ --decision-engine one_class_svm --kernel rbf --gamma 0.005
```

Evaluate the classification and generate a report containing different metrics:

```
./main.py evaluate --logfile classification-log.csv --output evaluation.json -d data/cic-ids-2017/MachineLearningCVE/ 
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


