# Introduction

This repository contains the code for my Bachelor's Thesis on "Comparing Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects". It provides a python program named *canids* (= **c**ompare **a**nomaly-based **NIDS**) that can be used
for developing, testing and evaluating anomaly-based network intrusion detection approaches while considering practical aspects, such as:

* only allowing one-class classification models which are trained in an unsupervised manner, with only *normal* (benign) network traffic as reference 

<!-- ToC start -->
# Table of Contents

<!-- ToC end -->

---

# Installation
## Manual

Clone the git repository and install the requirements with `pip install -r requirements.txt`. Python version 3.6 or higher is required. You can optionally also build the docker image locally:

```
❯ docker build . -t dhelmr/canids:latest -f docker/Dockerfile
```

## Docker

Alternatively, a [docker container available at docker hub](https://hub.docker.com/repository/docker/dhelmr/canids) can be used. In order to run, a data directory, which will contain the datasets and an database, must be mounted inside the container:

```shell
docker run -v $(pwd)/data:/data -it canids [CMDS]
```

In the following, the manual method is presumed, but all commands can be also run with docker. Just replace `bin/run_canids` with
`docker run -v $(pwd)/data:/data -it canids`.

# Dataset preparation

As a first step, the datasets need to be downloaded and preprocessed. This includes, for each network packet, the association of the corresponding network flow and thereby its label (benign or attack).




[here](https://cloudstor.aarnet.edu.au/plus/index.php/s/2DhnLGDdEECo4ys?path=%2F). The pcap files and CSV files need to be downloaded. 


```
insgesamt 2900
``` 

## Preprocessing

Afterwards, the datasets must be preprocessed once: 

```
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

## List decision engines and feature extractors

An anomaly detection model consists of:

2. one or more transformers, which map the extracted features to other numerical values (e.g. standardization)
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

## Simulate traffic, detect anomalies and create evaluation

First build and train a model by analyzing normal traffic:

```
```

Then read unknown traffic from a dataset and detect anomalies using the created model. The classifications will be written into an internal database.

```
```

Evaluate the classification. The metrics are stored in the sqlite database and,
 optionally, in a json file:

```
```

The evaluations can then be viewed with:

```
bin/run_canids list-evaluations
```

## Subsets

When only a part of a dataset should be read, the `--subset` parameter can be used. Its usage depends on the dataset.


Each weekday from Tuesday to Friday can be read in separately with `--subset [weekday]` as the test set which is used for classification.
Monday is always the training set. Example: `--subset wednesday`. 




In order to not read the whole dataset, it is possible to specify which pcaps will be loaded for the model training and testing. Those files which should be used can be specified with the

By default, that is when `--subset default` or nothing is specified, the following pcap files are used for the training step:

```

```

## Hypertune

For automation of the `train`->`classify`->`evaluate` pipeline, the `hypertune` command can be used. It reads a json file
as its input that contains directions for a hyperparameter search. Currently, only a brute-force grid search is implemented which iterates over all possible parameter combinations.
Examples for such files can be found in the `hypertune/` folder.


```
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

## Standalone Network Flow generator (optionally with payload analysis)

A standalone netflow generator CLI program can be run with `bin/extract_flows -r [pcap] -o [output csv path]`. 
It groups a pcap file's packets into netflows and generated features for each flow. 

```
❯ bin/extract_flows --help

usage: extract_flows [-h] -p PCAP -o OUTPUT [--payloads] [--payl] [--one-hot]

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

```

# License

The content of this repository is licensed under [GPLv3](LICENSE.txt).
