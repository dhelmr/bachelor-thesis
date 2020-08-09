Anomaly-based Network Intrusion Detection System written in python

**Work in Progress**

---

# Installation

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required.

# Dataset preparation

## CIC-IDS-2017

[Download](http://205.174.165.80/CICDataset/CIC-IDS-2017/) the dataset and extract the file `GeneratedLabelledFlows.zip`. The default path that is assumed for the dataset is 
`data/cic-ids-2017/MachineLearningCVE`, but another path can be specified with the option `--src` (see below). For now, only the preprocessed network flows will be used from this datasets.

Preprocess the dataset with 

```
> ./main.py preprocess cic-ids-2017 --src data/cic-ids-2017
```

# Usage

There are various subcommands:

```
❯ ./main.py --help

