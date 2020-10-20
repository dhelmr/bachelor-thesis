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

>>> one_class_svm <<<
usage: one_class_svm [-h] [--gamma GAMMA] [--nu NU]
                     [--kernel {rbf,poly,linear,sigmoid}]
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
  --kernel {rbf,poly,linear,sigmoid}
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


>>> local_outlier_factor <<<
usage: local_outlier_factor [-h]
                            [--metric {minkowski,cityblock,cosine,euclidean,l1,l2,manhattan,braycurtis,canberra,chebyshev,correlation,dice,hamming,jaccard,kulsinski,mahalanobis,rogerstanimoto,russellrao,seuclidean,sokalmichener,sokalsneath,sqeuclidean,yule}]
                            [--minkowski-p MINKOWSKI_P]
                            [--leaf-size LEAF_SIZE]
                            [--algorithm {auto,ball_tree,kd_tree,brute}]
                            [--n-neighbors N_NEIGHBORS]

optional arguments:
  -h, --help            show this help message and exit
  --metric {minkowski,cityblock,cosine,euclidean,l1,l2,manhattan,braycurtis,canberra,chebyshev,correlation,dice,hamming,jaccard,kulsinski,mahalanobis,rogerstanimoto,russellrao,seuclidean,sokalmichener,sokalsneath,sqeuclidean,yule}
                        Distance metric that is used for LOF (default:
                        minkowski)
  --minkowski-p MINKOWSKI_P
                        Parameter p when metric='minkowski' (default: 2)
  --leaf-size LEAF_SIZE
                        This canaffect the speed of the construction and
                        query, as well as the memory required to store the
                        tree. The optimal value depends on the nature of the
                        problem. (default: 30)
  --algorithm {auto,ball_tree,kd_tree,brute}
                        Algorithm used to compute the nearest neighbors with
                        LOF (default: auto)
  --n-neighbors N_NEIGHBORS
                        Number of neighbors to use by default for kneighbors
                        queries. If n_neighbors is larger than the number of
                        samples provided, all samples will be used. (default:
                        20)


>>> autoencoder <<<
usage: autoencoder [-h] [--training-epochs TRAINING_EPOCHS]
                   [--training-batch TRAINING_BATCH] [--layers LAYERS]
                   [--activation {relu,sigmoid,softmax,softplus,softsign,tanh,selu,elu,exponential}]
                   [--loss {mse,mae}] [--verbose]

optional arguments:
  -h, --help            show this help message and exit
  --training-epochs TRAINING_EPOCHS
  --training-batch TRAINING_BATCH
  --layers LAYERS
  --activation {relu,sigmoid,softmax,softplus,softsign,tanh,selu,elu,exponential}
  --loss {mse,mae}
  --verbose



```

As you can see, feature extractors and decision engines can take additional CLI parameters. Those can just be added when specifying them in the `train` command (see examples below).

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


