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
usage: PROG [-h] [--dataset-path DATASET_PATH] {simulate,evaluate} ...

positional arguments:
  {simulate,evaluate}   sub-command help
    simulate            Feed traffic from a dataset and detect anomalies.
    evaluate            Generate an evaluation report from a log file.

optional arguments:
  -h, --help            show this help message and exit
  --dataset-path DATASET_PATH, -dp DATASET_PATH
                        Path of the dataset

```

## Simulate traffic, detect anomalies and create evaluation report

Read the traffic from a dataset and detect anomalies. The classifications will be written into a csv file:

```
./main.py -dp data/cic-ids-2017/MachineLearningCVE/ simulate --output classification-log.csv
```

Evaluate the classification and generate a report containing precision, recall and f1-scores:

```
./main.py -dp data/cic-ids-2017/MachineLearningCVE/ evaluate --logfile classification-log.csv
```

Example output: 

```
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
              precision    recall  f1-score   support

      BENIGN       0.55      0.84      0.66     97718
      ATTACK       0.79      0.47      0.59    128027

    accuracy                           0.63    225745
   macro avg       0.67      0.66      0.63    225745
weighted avg       0.69      0.63      0.62    225745

Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
              precision    recall  f1-score   support

      BENIGN       0.45      1.00      0.62    127537
      ATTACK       0.23      0.00      0.00    158930

    accuracy                           0.44    286467
   macro avg       0.34      0.50      0.31    286467
weighted avg       0.33      0.44      0.27    286467
```

