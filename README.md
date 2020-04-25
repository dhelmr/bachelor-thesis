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
    evaluate            Generate an evaluation report from a log file.
    list-de             Lists the available decision engines

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type, for example:

```
❯ ./main.py simulate --help

usage: main.py simulate [-h] [--logfile LOGFILE]
                        [--decision-engine {one_class_svm}]
                        [--dataset-path DATASET_PATH]

optional arguments:
  -h, --help            show this help message and exit
  --logfile LOGFILE, -l LOGFILE
                        Log file where the predictions will be written into
                        (default: log-2020-04-25 21:10:27.347375.csv)
  --decision-engine {one_class_svm}
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

```

## Simulate traffic, detect anomalies and create evaluation report

Read the traffic from a dataset and detect anomalies. The classifications will be written into a csv file:

```
./main.py simulate --logfile classification-log.csv -d data/cic-ids-2017/MachineLearningCVE/
```

Evaluate the classification and generate a report containing precision, recall and f1-scores:

```
./main.py evaluate --logfile classification-log.csv --output evaluation_report.txt -d data/cic-ids-2017/MachineLearningCVE/ 
```

Example content of the resulting report: 

```
❯ cat evaluation_report.txt | head -n 16

>>> Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
              precision    recall  f1-score   support

      BENIGN       0.62      0.80      0.70     97718
      ATTACK       0.81      0.63      0.71    128027

    accuracy                           0.70    225745
   macro avg       0.71      0.72      0.70    225745
weighted avg       0.73      0.70      0.70    225745
>>> Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
              precision    recall  f1-score   support

      BENIGN       0.44      1.00      0.62    127537
      ATTACK       0.34      0.00      0.00    158930

    accuracy                           0.44    286467

```


