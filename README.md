# Introduction

This repository contains the code for my bachelor's thesis on "Comparing Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects". It provides a python program named *canids* (= **c**ompare **a**nomaly-based **NIDS**) that can be used
for developing, testing and evaluating anomaly-based network intrusion detection approaches while considering practical aspects, such as:

* only allowing one-class classification models which are trained in an unsupervised manner, with only *normal* (benign) network traffic as reference 
* taking raw network packets (as PCAPs) as the input (the modern UNSW-NB15 and CIC-IDS-2017 datasets can be used for this) 
* measuring the performance of a model through various metrics (precision, recall, MCC, f1-score, balanced accuracy or the classification time per packet)

The full text of the bachelor's thesis can be [accessed here](https://nbn-resolving.de/urn:nbn:de:bsz:15-qucosa2-753859) ([Direct PDF Link](https://ul.qucosa.de/api/qucosa%3A75385/attachment/ATT-0/)).

<!-- ToC start -->
# Table of Contents

1. [Introduction](#introduction)
1. [Installation](#installation)
   1. [Manual](#manual)
   1. [Docker](#docker)
1. [Dataset Preparation](#dataset-preparation)
   1. [CIC-IDS-2017](#cic-ids-2017)
   1. [UNSW-NB-15](#unsw-nb-15)
   1. [Preprocessing](#preprocessing)
1. [Usage](#usage)
   1. [List Decision Engines and Feature Extractors](#list-decision-engines-and-feature-extractors)
   1. [Train Model, Simulate Unknown Traffic, Detect Anomalies and Evaluate](#train-model-simulate-unknown-traffic-detect-anomalies-and-evaluate)
   1. [Subsets](#subsets)
         1. [CIC-IDS-2017 subsets](#cic-ids-2017-subsets)
         1. [UNSW-NB15 Subsets](#unsw-nb15-subsets)
   1. [Hyperparameter Search](#hyperparameter-search)
   1. [Report](#report)
   1. [Visualize](#visualize)
1. [Misc](#misc)
   1. [Standalone Network Flow Generator (Optionally with Payload Analysis)](#standalone-network-flow-generator-optionally-with-payload-analysis)
   1. [Slurm scripts and jobs](#slurm-scripts-and-jobs)
   1. [Testing](#testing)
1. [License](#license)
<!-- ToC end -->

---

# Installation
## Manual

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required. You can optionally also build the docker image locally:

```
❯ docker build . -t dhelmr/canids:latest -f docker/Dockerfile
```

## Docker

Alternatively, a [docker container available at docker hub](https://hub.docker.com/r/dhelmr/canids) can be used. In order to run, a data directory, which will contain the datasets and an database, must be mounted inside the container:

```shell
docker run -v $(pwd)/data:/data -it dhelmr/canids [CMDS]
```

In the following, the manual method is presumed, but all commands can be also run with docker. Just replace `bin/run_canids` with
`docker run -v $(pwd)/data:/data -it dhelmr/canids`.

# Dataset Preparation

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
❯  bin/run_canids preprocess --dataset cic-ids-2017 
❯  bin/run_canids preprocess --dataset unsw-nb15
```

# Usage

There are various subcommands:

```
❯ bin/run_canids --help

usage: run_canids [-h]
                  {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,list-evaluations,migrate-db,hypertune,visualize,stats,report}
                  ...

positional arguments:
  {train,classify,evaluate,list-de,list-classifications,list-fe,preprocess,list-models,list-evaluations,migrate-db,hypertune,visualize,stats,report}
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
                        classification and evaluation afterwards.
    list-models         List available models.
    list-evaluations    Prints evaluations.
    migrate-db          Migrates database schema. Can also be used to create a
                        new database.
    hypertune           Hypertunes parameters of decision engine and feature
                        extractor by running the train->classify->evaluate
                        pipeline multiple times.
    visualize           Visualizes evaluations
    stats               Print stats for a dataset
    report              Creates a textual report for the evaluations.

optional arguments:
  -h, --help            show this help message and exit

```

For help of the subcommands just type `--help`, for example:

```
❯ bin/run_canids train --help
```

## List Decision Engines and Feature Extractors

An anomaly detection model consists of:

1. a feature extractor, which processes raw pcap files and maps them to numerical values
2. an arbitrary number of transformers, which map the extracted features to other numerical values (e.g. standardization)
3. a decision engine which decides whether a feature vector is an anomaly or not

Feature extractors can be listed with:

```
❯ bin/run_canids list-fe --short

flow_extractor
flows_payload
payl_flows

```

You can list available decision engines with `bin/run_canids list-de` or:

```
❯ bin/run_canids list-de --short

autoencoder
local_outlier_factor
isolation_forest
one_class_svm

```

Without `--short`, more information will be printed. Then you can see, that feature extractors and decision engines can take additional CLI parameters. Those can just be added when specifying them in the `train` command (see examples below).

Available feature transformers are:

```
minmax_scaler
standard_scaler
onehot_encoder
pca_reducer_20
pca_reducer_30
pca_reducer_10
pca_reducer_50
fixed_feature_name_filter

```

## Train Model, Simulate Unknown Traffic, Detect Anomalies and Evaluate

First build and train a model by analyzing normal traffic (in this example with the netflow generator, the One-Hot encoder, the minmax scaler and a rbf one-class SVM):

```
bin/run_canids train --src data/cic-ids-2017 --dataset cic-ids-2017 --feature-extractor flow_extractor --nf-mode tcp subflows --transformers onehot_encoder minmax_scaler --model-id oc_svm --decision-engine one_class_svm --kernel rbf --gamma 0.005
```

Then read unknown traffic from a dataset and detect anomalies using the created model. The classifications will be written into an internal database.

```
bin/run_canids classify --src data/cic-ids-2017 --dataset cic-ids-2017  --id oc_svm_c1 --model-id oc_svm
```

Evaluate the classification. The metrics are stored in the sqlite database and,
 optionally, in a json file:

```
bin/run_canids evaluate --src data/cic-ids-2017 --dataset cic-ids-2017 -id oc_svm_1 --output evaluation.json 
```

The evaluations can then be viewed with:

```
bin/run_canids list-evaluations
```

## Subsets

When only a part of a dataset should be read, the `--subset` parameter can be used. Its usage depends on the dataset.

#### CIC-IDS-2017 subsets

Each weekday from Tuesday to Friday can be read in separately with `--subset [weekday]` as the test set which is used for classification.
Monday is always the training set. Example: `--subset wednesday`. 

Hint: The attack distributions over the weekdays can be printed with: `python main.py stats --dataset cic-ids-2017`.

#### UNSW-NB15 Subsets

In order to not read the whole dataset, it is possible to specify which pcaps will be loaded for the model training and testing. Those files which should be used can be specified with the
following syntax: `--subset [training split]/[test split]`. For example, `--subset 1-10,14/43` uses the first ten pcap files
and the 14th for the training step (by first filtering out all attack instances in it) and the 43th for the classification. These indexes correspond to the files in the `01/` and `02/` directories, sorted in ascending order: For example, `14` denotes `01/14.pcap`, and `54` denotes `02/1.pcap`.

By default, that is when `--subset default` or nothing is specified, the following pcap files are used for the training step:

```
['01/23.pcap', '01/24.pcap', '01/25.pcap', '01/26.pcap', '01/27.pcap']

```

There are also predefined subsets which are called `A`,`B` (for training), `a`,`b`, and `c` (for classification).

## Hyperparameter Search

For automation of the `train`->`classify`->`evaluate` pipeline, the `hypertune` command can be used. It reads a json file
as its input that contains directions for a hyperparameter search. Currently, only a brute-force grid search is implemented which iterates over all possible parameter combinations.
Examples for such files can be found in the `hypertune/` folder.

For example, a set of different parameter configurations for an autoencoder on the unsw-nb15 dataset can be run with:

```
❯ bin/run_canids hypertune -f hypertune/autoencoder/best_ae.json --dataset unsw-nb15 --subset 1-5/15,55,56
```

The results of the evaluations can then be viewed in the sqlite database (`classifications.db` by default).

## Report

A csv report can be created with the `report` command:

```
❯ bin/run_canids report --model-part-name autoencoder flow_extractor --format csv --all -o autoencoder_flow_extractor_report.csv
```

It contains the chosen parameters for each model and the classifications that were ran with it, together with the calculated evaluation metrics. The `--model-part-name` parameter specifies which model components are incorporated into the report.

## Visualize

For visualizing the results of multiple evaluations of one feature extractor or decision engine, the `visualize` command can be used. For example, the following generates a html visualization of all autoencoders models into the directory `data/visualizations`:

```
❯ bin/run_canids visualize --model-part-name autoencoder --output data/visualizations
```

# Misc

## Standalone Network Flow Generator (Optionally with Payload Analysis)

A standalone netflow generator CLI program can be run with `bin/extract_flows -r [pcap] -o [output csv path]`. 
It groups a pcap file's packets into netflows and generated features for each flow. 

```
❯ bin/extract_flows --help

usage: extract_flows [-h] -p PCAP -o OUTPUT [--payloads] [--payl] [--one-hot]
                     [--flow-timeout FLOW_TIMEOUT]
                     [--subflow-timeout SUBFLOW_TIMEOUT]
                     [--hindsight-window HINDSIGHT_WINDOW] [--verbose]
                     [--nf-mode {subflows,with_ip_addr,tcp,include_header_length,hindsight,ip_dotted,port_decimal,basic,tcp_end_on_rst} [{subflows,with_ip_addr,tcp,include_header_length,hindsight,ip_dotted,port_decimal,basic,tcp_end_on_rst} ...]]

optional arguments:
  -h, --help            show this help message and exit
  -p PCAP, --pcap PCAP  Pcap file to read
  -o OUTPUT, --output OUTPUT
                        CSV output file to write
  --payloads            Analyse payloads with NetflowPayloadAnalyser. It
                        creates an own feature with the frequency for every
                        byte in a payload.
  --payl                Analyse payloads with PAYL.
  --one-hot             Onehot-encode categorial features
  --flow-timeout FLOW_TIMEOUT
                        Flow timeout in seconds
  --subflow-timeout SUBFLOW_TIMEOUT
                        Activity timeout (for subflows) in seconds
  --hindsight-window HINDSIGHT_WINDOW
                        Hindsight window; only used with netflow mode
                        'hindsight'
  --verbose
  --nf-mode {subflows,with_ip_addr,tcp,include_header_length,hindsight,ip_dotted,port_decimal,basic,tcp_end_on_rst} [{subflows,with_ip_addr,tcp,include_header_length,hindsight,ip_dotted,port_decimal,basic,tcp_end_on_rst} ...]
                        Feature Selection Modes

```

For example, the following line applies the PAYL extractor using the modes `subflows`, `tcp`, and `with_ip_addr` on the packets from the file `traffic.pcap` and writes the extracted features to `features.csv`:

```shell
bin/extract_flows -p traffic.pcap --payl --nf-mode subflows with_ip_addr tcp -o features.csv
```

## Slurm scripts and jobs

The directory `dev/` contains several files that can be useful for running the hyperparameter search experiments from 
`hypertune/` in a [slurm](https://slurm.schedmd.com/overview.html) environment.

## Testing

The `test/` directory contains both unit and integration tests. The unit tests can be run with `python -m unittest discover test/`. The integration tests require the docker container and can be run with `test/integration-tests/run.sh
`.

# License

The content of this repository is licensed under [GPLv3](LICENSE.txt).

