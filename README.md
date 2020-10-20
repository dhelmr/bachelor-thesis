Anomaly-based Network Intrusion Detection System written in python

**Work in Progress**

---

# Installation

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required.

# Dataset preparation

## CIC-IDS-2017

[Download](http://205.174.165.80/CICDataset/CIC-IDS-2017/) the dataset and extract the file `GeneratedLabelledFlows.zip`. The default path that is assumed for the dataset is 
`data/cic-ids-2017`, but another path can be specified with the option `--src` (see below). For now, only the preprocessed network flows will be used from this datasets.

## UNSW-NB-15

The dataset decription can be found [here](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/). It can be downloaded
[here](https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2F). The pcap files and CSV files need to be downloaded. 

The pcap files must be extracted to directories named `01` (files from [22-1-2015](https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys)) 
and `02` (files from [17-2-2015](https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys)). Thus, the resulting directory structure must be like this:

```
❯ ls -l ./data/unsw-nb15/
insgesamt 2900
drwxr-xr-x 2 daniel users 1036288 17. Okt 21:57  01/
drwxr-xr-x 2 daniel users    4096  8. Okt 19:12  02/
drwxr-xr-x 3 daniel users    4096 17. Okt 10:44 'UNSW-NB15 - CSV Files'/
``` 

## Preprocessing

Afterwards, the datasets must be preprocessed once: 

```
❯  ./main.py preprocess --dataset cic-ids-2017 
❯  ./main.py preprocess --dataset unsw-nb15
```

# Usage

There are various subcommands:

```
❯ ./main.py --help

usage: main.py [-h]
               {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,hypertune}
               ...

positional arguments:
  {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,hypertune}
    train               Creates a classification model from analyzing normal
                        traffic and stores it in the database.
    classify            Feed traffic from a dataset and detect anomalies.
    evaluate            Generate an evaluation report in JSON format from a
                        prediction log.
    list-de             Lists the available decision engines
    list-classifications
                        Lists all anomaly classifications that were previously
                        run.
    list-fe             Lists all available feature extractors
    preprocess          Preprocesses a dataset so that it can be used for
                        evaluation afterwards.
    list-models         List available models.
    hypertune           Hypertunes parameters of decision engine and feature
                        extractor by running the train->classify->evaluate
                        pipeline multiple times.

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type `--help`, for example:

```
❯ ./main.py train --help)
```

## List decision engines and feature extractors

An anomaly detection model consists of:

1. a feature extractor, which processes raw pcap files and maps them to numerical values
2. one or more transformers, which map the extracted features to other numerical values (e.g. standardization)
3. a decision engine which decides whether a feature vector is an anomaly or not

Feature extractors can be listed with:

```
❯ ./main.py list-fe

>>> basic_netflow <<<
usage: main.py [-h] [--flow-timeout FLOW_TIMEOUT]
               [--subflow-timeout SUBFLOW_TIMEOUT] [--verbose]
               [--nf-mode {subflows_detailed,subflows_simple,with_ip,tcp} [{subflows_detailed,subflows_simple,with_ip,tcp} ...]]

optional arguments:
  -h, --help            show this help message and exit
  --flow-timeout FLOW_TIMEOUT
                        Flow timeout in milliseconds
  --subflow-timeout SUBFLOW_TIMEOUT
                        Activity timeout (for subflows) in milliseconds
  --verbose
  --nf-mode {subflows_detailed,subflows_simple,with_ip,tcp} [{subflows_detailed,subflows_simple,with_ip,tcp} ...]
                        Feature Selection Modes


>>> basic_packet_info <<<
usage: main.py [-h]

optional arguments:
  -h, --help  show this help message and exit


>>> doc2vec_packet <<<
usage: main.py [-h]

optional arguments:
  -h, --help  show this help message and exit


>>> doc2vec_flows <<<
usage: main.py [-h] [--flow-timeout FLOW_TIMEOUT]
               [--subflow-timeout SUBFLOW_TIMEOUT] [--verbose]
               [--nf-mode {subflows_detailed,subflows_simple,with_ip,tcp} [{subflows_detailed,subflows_simple,with_ip,tcp} ...]]
               [--d2v-vector-size VECTOR_SIZE] [--d2v-workers WORKERS]
               [--d2v-window MIN_COUNT] [--d2v-min-count WINDOW]

optional arguments:
  -h, --help            show this help message and exit
  --flow-timeout FLOW_TIMEOUT
                        Flow timeout in milliseconds
  --subflow-timeout SUBFLOW_TIMEOUT
                        Activity timeout (for subflows) in milliseconds
  --verbose
  --nf-mode {subflows_detailed,subflows_simple,with_ip,tcp} [{subflows_detailed,subflows_simple,with_ip,tcp} ...]
                        Feature Selection Modes
  --d2v-vector-size VECTOR_SIZE
  --d2v-workers WORKERS
  --d2v-window MIN_COUNT
  --d2v-min-count WINDOW


>>> test <<<
usage: main.py [-h]

optional arguments:
  -h, --help  show this help message and exit



```

You can list available decision engines with `./main.py list-de --short` or:

```
❯ ./main.py list-de --short

one_class_svm
local_outlier_factor
autoencoder

```

Without `--short`, more information will be printed. Then you can see, that feature extractors and decision engines can take additional CLI parameters. Those can just be added when specifying them in the `train` command (see examples below).

## Simulate traffic, detect anomalies and create evaluation report

First build and train a model by analyzing normal traffic:

```
./main.py train --model-id oc_svm --src data/cic-ids-2017/MachineLearningCVE/ --decision-engine one_class_svm --kernel rbf --gamma 0.005
```

Then read unknown traffic from a dataset and detect anomalies using the created model. The classifications will be written into an internal database.

```
./main.py classify --id oc_svm_c1 --src data/cic-ids-2017/MachineLearningCVE/ --model-id oc_svm 
```

Evaluate the classification and generate a report containing different metrics:

```
./main.py evaluate --id oc_svm_1 --output evaluation.json --src data/cic-ids-2017/MachineLearningCVE/ --force-overwrite
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


# Misc

A standalone netflow generator CLI program can be run with `python netflows.py -r [pcap] -o [features.csv]`. 
It groups a pcap file's packets into netflows and generated features for each flow.
