# Comparison of Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects

Note: This repository is **work in progress**.

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
               {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,hypertune,stats}
               ...

positional arguments:
  {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,hypertune,stats}
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
    stats               Print stats for a dataset

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type `--help`, for example:

```
❯ ./main.py train --help
```

## List decision engines and feature extractors

An anomaly detection model consists of:

1. a feature extractor, which processes raw pcap files and maps them to numerical values
2. one or more transformers, which map the extracted features to other numerical values (e.g. standardization)
3. a decision engine which decides whether a feature vector is an anomaly or not

Feature extractors can be listed with:

```
❯ ./main.py list-fe --short

basic_netflow
basic_packet_info
doc2vec_packet
doc2vec_flows
test

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

Evaluate the classification and generate a report containing different metrics. The metrics are stored in the sqlite database and,
 optionally, in a json file:

```
./main.py evaluate --id oc_svm_1 --output evaluation.json --src data/cic-ids-2017/MachineLearningCVE/
```

Example content of the resulting report: 

```
❯ cat evaluation.json | head -n 32

{
    "all": {
        "01/15.pcap@UNSW-NB15:unknown": {
            "accuracy": 0.9987106908440785,
            "balanced_accuracy": Infinity,
            "f1_score": 0.0,
            "false_negatives": 0,
            "false_positives": 2400,
            "fdr": 1.0,
            "fnr": Infinity,
            "for": 0.0,
            "fpr": 0.0012893091559215283,
            "kappa": 0.0,
            "mcc": Infinity,
            "negatives": 1861462,
            "npv": 1.0,
            "positives": 0,
            "precision": 0.0,
            "recall": Infinity,
            "support": 1861462,
            "tnr": 0.9987106908440785,
            "true_negatives": 1859062,
            "true_positives": 0
        },
        "02/2.pcap@UNSW-NB15:unknown": {
            "accuracy": 0.9852358261224796,
            "balanced_accuracy": 0.7597047176356007,
            "f1_score": 0.6776935096611914,
            "false_negatives": 49272,
            "false_positives": 1470,
            "fdr": 0.026816987740805605,
            "fnr": 0.48014968134245456,

```

## Hypertune

For automation of the `train`->`classify`->`evaluate` pipeline, the `hypertune` command can be used. It reads a json file
as its input that contains directions for a hyperparameter search. Currently, only a brute-force grid search is implemented which iterates over all possible parameter combinations.
Examples for such files can be found in the `hypertune/` folder.

For example, a set of different parameter configurations for a autoencoder on the unsw-nb15 dataset can be run with:

```
❯ python main.py hypertune -f hypertune/ae.json --dataset unsw-nb15
```

The results of the evaluations can then be viewed in the sqlite database (`classifications.db` by default).

# Misc

A standalone netflow generator CLI program can be run with `python netflows.py -r [pcap] -o [features.csv]`. 
It groups a pcap file's packets into netflows and generated features for each flow.
