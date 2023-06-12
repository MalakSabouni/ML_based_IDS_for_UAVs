# ML-based IDS for UAV

This repository contains the code and resources for implementing a Machine Learning-based Intrusion Detection System (IDS) for UAV (Unmanned Aerial Vehicles) networks. The IDS is designed to detect and classify malicious behavior in Tello Ryze Tech drones. The dataset used for training and testing the models was collected from scratch by contributors using the nfstream tool (https://www.nfstream.org/docs/api).

# Repository Description
The following is a brief description of the files in this repository:

**ml-ids-uav-final.ipynb**: This Jupyter Notebook file contains the code for building, training, and testing the main machine learning models.

**nfst_dataset.py**: This script is used for feature extraction to create the dataset.

**nic.sh**: This script automates the configuration of the NIC (Network Interface Card) monitoring interface.

**uav_ml_ids.py**: This is the main IDS deployment file that utilizes a two-stage classification approach. The first stage employs novelty detection, while the second stage classifies the anomalies into potential attack types.

# Dependencies
To run the uav_ml_ids.py script, the following dependencies are required:

**nfstream**: The nfstream library is a main dependency for the IDS.

**Sudo Privilege**: Administrative privileges are required for running the script.

# Folder Structure
The repository is organized into the following folders:

**logs**: This folder contains the logs of the IDS.
**models**: The exported models are stored in this folder.
**dataset**: The collected dataset is stored in this folder.
**attacks_scripts**: contains scripts used to launch attacks on tello drone and collect malicious dataset
Please refer to the individual files for more detailed information on their usage and functionalities.

Feel free to contribute to this repository by creating pull requests and reporting any issues you encounter.
