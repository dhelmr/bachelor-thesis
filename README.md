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

usage: main.py [-h] {simulate,evaluate} ...

positional arguments:
  {simulate,evaluate}
    simulate           Feed traffic from a dataset and detect anomalies.
    evaluate           Generate an evaluation report from a log file.

optional arguments:
  -h, --help           show this help message and exit

```

## Simulate traffic, detect anomalies and create evaluation report

Read the traffic from a dataset and detect anomalies. The classifications will be written into a csv file:

```
./main.py simulate --logfile classification-log.csv -dp data/cic-ids-2017/MachineLearningCVE/
```

Evaluate the classification and generate a report containing precision, recall and f1-scores:

```
./main.py evaluate --logfile classification-log.csv --output evaluation_report.txt -dp data/cic-ids-2017/MachineLearningCVE/ 
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


