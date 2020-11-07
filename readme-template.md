# Comparison of Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects

Note: This repository is **work in progress**.

<!-- ToC start -->
<!-- ToC end -->

---


# Installation

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required.

# Dataset preparation

As a first step, the datasets need to be downloaded and preprocessed. This includes, for each network packet, the association of the corresponding network flow and thereby its label (benign or attack).

## CIC-IDS-2017

[Download](http://205.174.165.80/CICDataset/CIC-IDS-2017/) the dataset and extract the file `GeneratedLabelledFlows.zip`. The default path that is assumed for the dataset is 
`data/cic-ids-2017`, but another path can be specified with the option `--src` (see below). 

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
$(./main.py --help)
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
$(./main.py list-fe --short)
```

You can list available decision engines with `./main.py list-de --short` or:

```
$(./main.py list-de --short)
```

Without `--short`, more information will be printed. Then you can see, that feature extractors and decision engines can take additional CLI parameters. Those can just be added when specifying them in the `train` command (see examples below).

## Simulate traffic, detect anomalies and create evaluation report

First build and train a model by analyzing normal traffic:

```
./main.py train --src data/cic-ids-2017 --dataset cic-ids-2017 --model-id oc_svm --decision-engine one_class_svm --kernel rbf --gamma 0.005
```

Then read unknown traffic from a dataset and detect anomalies using the created model. The classifications will be written into an internal database.

```
./main.py classify --src data/cic-ids-2017 --dataset cic-ids-2017  --id oc_svm_c1 --model-id oc_svm
```

Evaluate the classification and generate a report containing different metrics. The metrics are stored in the sqlite database and,
 optionally, in a json file:

```
./main.py evaluate --src data/cic-ids-2017 --dataset cic-ids-2017 -id oc_svm_1 --output evaluation.json 
```

Example content of the resulting report: 

```
$(cat evaluation.json | head -n 32)
```

## Subsets

When only a part of a dataset should be read, the `--subset` parameter can be used. Its usage depends on the dataset.

#### CIC-IDS-2017 subsets

Each weekday from Tuesday to Friday can be read in separately with `--subset [weekday]` as the test set which is used for classification.
Monday is always the training set. Example: `--subset wednesday`. 

Hint: The attack distributions over the weekdays can be printed with: `python main.py stats --dataset cic-ids-2017`.

#### UNSW-NB15 Subsets

Only a specific pcaps of the dataset can be read. Those files which should be used can be specified with the
following syntax: `--subset [training split]/[test split]`. For example, `--subset 1-10,14/43` uses the first ten pcap files
and the 14th for the training step (by first filtering out all attack instances in it) and the 43th for the classification.

By default, that is when `--subset default` or nothing is specified, the following pcap files are used for the training step:

```
-$(python -c "from dataset_utils.unsw_nb15 import DEFAULT_BENIGN_PCAPS;print(DEFAULT_BENIGN_PCAPS)")
```

## Hypertune

For automation of the `train`->`classify`->`evaluate` pipeline, the `hypertune` command can be used. It reads a json file
as its input that contains directions for a hyperparameter search. Currently, only a brute-force grid search is implemented which iterates over all possible parameter combinations.
Examples for such files can be found in the `hypertune/` folder.

For example, a set of different parameter configurations for a autoencoder on the unsw-nb15 dataset can be run with:

```
❯ python main.py hypertune -f hypertune/ae.json --dataset unsw-nb15 --subset 1-5/15,55,56
```

The results of the evaluations can then be viewed in the sqlite database (`classifications.db` by default).

# Misc

A standalone netflow generator CLI program can be run with `python netflows.py -r [pcap] -o [features.csv]`. 
It groups a pcap file's packets into netflows and generated features for each flow.

```
$(python netflows.py --help)
```
