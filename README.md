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
❯ ./main.py train --help

usage: main.py train [-h] [--db DB] [--debug]
                     [--transformers {minmax_scaler,standard_scaler,onehot_encoder} [{minmax_scaler,standard_scaler,onehot_encoder} ...]]
                     [--feature-extractor {basic_netflow,basic_packet_info,doc2vec_packet,doc2vec_flows,test}]
                     [--store-features] [--load-features]
                     [--model-id MODEL_ID]
                     [--decision-engine {one_class_svm,local_outlier_factor,autoencoder}]
                     [--dataset {cic-ids-2017,unsw-nb15,test}]
                     [--src DATASET_PATH] [--subset DATASET_SUBSET]

optional arguments:
  -h, --help            show this help message and exit
  --db DB               Database file where the classifications are stored.
                        (default: classifications.db)
  --debug, --verbose    Will produce verbose output that is useful for
                        debugging (default: False)
  --transformers {minmax_scaler,standard_scaler,onehot_encoder} [{minmax_scaler,standard_scaler,onehot_encoder} ...], -t {minmax_scaler,standard_scaler,onehot_encoder} [{minmax_scaler,standard_scaler,onehot_encoder} ...]
                        Specifies one or more transformers that are applied
                        before calling the decision engine. (default: [])
  --feature-extractor {basic_netflow,basic_packet_info,doc2vec_packet,doc2vec_flows,test}, -f {basic_netflow,basic_packet_info,doc2vec_packet,doc2vec_flows,test}
                        Specifies the feature extractor that is used to
                        generate features from the raw network traffic.
                        (default: basic_netflow)
  --store-features      Stores the extraced features in the database, so that
                        they can be reused later. (default: False)
  --load-features       Loads features from a previous run, instead of
                        executing the feature extractor.This is only possible
                        if the feature extractor ran before with this exact
                        configuration and the traffic input is consistent.
                        (default: False)
  --model-id MODEL_ID, -m MODEL_ID
                        ID of the model. If auto is used, the model ID will be
                        auto-generated. (default: auto)
  --decision-engine {one_class_svm,local_outlier_factor,autoencoder}
                        Choose which algorithm will be used for classifying
                        anomalies. (default: one_class_svm)
  --dataset {cic-ids-2017,unsw-nb15,test}, -d {cic-ids-2017,unsw-nb15,test}
                        The name of the dataset. Choose one of: ['cic-
                        ids-2017', 'unsw-nb15', 'test'] (default: cic-
                        ids-2017)
  --src DATASET_PATH    Path of the dataset (default:
                        /mnt/data/ba/code/data/cic-ids-2017/)
  --subset DATASET_SUBSET
                        Predefined subset of the dataset (default: default)

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
❯ ./main.py list-de

