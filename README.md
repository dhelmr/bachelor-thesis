# Comparison of Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects

Note: This repository is **work in progress**.

<!-- ToC start -->
# Table of Contents

1. [Comparison of Anomaly-Based Network Intrusion Detection Approaches Under Practical Aspects](#comparison-of-anomaly-based-network-intrusion-detection-approaches-under-practical-aspects)
   1. [](#)
1. [Installation](#installation)
1. [Dataset preparation](#dataset-preparation)
   1. [CIC-IDS-2017](#cic-ids-2017)
   1. [UNSW-NB-15](#unsw-nb-15)
   1. [Preprocessing](#preprocessing)
   1. [Docker](#docker)
1. [Usage](#usage)
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
❯  bin/run_canids preprocess --dataset cic-ids-2017 
❯  bin/run_canids preprocess --dataset unsw-nb15
```

## Docker

You can also build a docker image to run the commands of the next sections inside a container:

```
❯ docker build . -t canids:latest -f docker/Dockerfile
```

In order to run, the data directory must be mounted inside the container:

```
docker run -v (pwd)/data:/data -it canids [CMDS]
```

# Usage

There are various subcommands:

```
❯ bin/run_canids --help

