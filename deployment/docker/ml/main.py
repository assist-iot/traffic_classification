#!/usr/bin/python3


import os
from io import BytesIO
import sys
from pathlib import Path
from joblib import Parallel, delayed
import torch
from torch.nn import functional as F
import numpy as np

import psutil
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, ArrayType, LongType, DoubleType

from utils import read_pcap, ID_TO_APP, ID_TO_TRAFFIC
from ml.utils import (train_application_classification_resnet_model, train_traffic_classification_resnet_model,
                      train_application_classification_cnn_model, train_traffic_classification_cnn_model, load_traffic_classification_resnet_model, load_traffic_classification_cnn_model, load_application_classification_resnet_model, load_application_classification_cnn_model)
from ml.preprocessing import transform_packet, transform_pcap
from ml.create_train_test_set import create_train_test_for_task, print_df_label_distribution
########### PREPROCESSING.PY ##############################


def preprocess(source, target, njob):
    # Path to the directory containing raw pcap files
    data_dir_path = Path(source)
    target_dir_path = Path(target)
    target_dir_path.mkdir(parents=True, exist_ok=True)
    if njob == 1:
        for pcap_path in sorted(data_dir_path.iterdir()):
            transform_pcap(
                pcap_path, target_dir_path / (pcap_path.name + ".transformed")
            )
    else:
        Parallel(n_jobs=njob)(
            delayed(transform_pcap)(
                pcap_path, target_dir_path / (pcap_path.name + ".transformed")
            )
            for pcap_path in sorted(data_dir_path.iterdir())
        )
    return {"Result": "Pre-processing completed successfully"}


def create_train_test_set(source, target, test_size, under_sampling):
    source_data_dir_path = Path(source)
    target_data_dir_path = Path(target)

    # prepare dir for dataset
    application_data_dir_path = target_data_dir_path / "application_classification"
    traffic_data_dir_path = target_data_dir_path / "traffic_classification"

    # initialise local spark
    os.environ["PYSPARK_PYTHON"] = sys.executable
    os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable
    memory_gb = psutil.virtual_memory().available // 1024 // 1024 // 1024
    spark = (
        SparkSession.builder.master("local[*]")
        .config("spark.driver.memory", f"{memory_gb}g")
        .config("spark.driver.host", "127.0.0.1")
        .getOrCreate()
    )

    # read data
    schema = StructType(
        [
            StructField("app_label", LongType(), True),
            StructField("traffic_label", LongType(), True),
            StructField("feature", ArrayType(DoubleType()), True),
        ]
    )

    df = spark.read.schema(schema).json(
        f"{source_data_dir_path.absolute().as_uri()}/*.json.gz"
    )

    # prepare data for application classification and traffic classification
    print("processing application classification dataset")
    create_train_test_for_task(
        df=df,
        label_col="app_label",
        test_size=test_size,
        under_sampling=under_sampling,
        data_dir_path=application_data_dir_path,
    )

    print("processing traffic classification dataset")
    create_train_test_for_task(
        df=df,
        label_col="traffic_label",
        test_size=test_size,
        under_sampling=under_sampling,
        data_dir_path=traffic_data_dir_path,
    )

    # stats
    print_df_label_distribution(
        spark, application_data_dir_path / "train.parquet")
    print_df_label_distribution(
        spark, application_data_dir_path / "test.parquet")
    print_df_label_distribution(spark, traffic_data_dir_path / "train.parquet")
    print_df_label_distribution(spark, traffic_data_dir_path / "test.parquet")
    return {"Result": "Successfully created"}


def train(data_path, model_path, model_type, task):
    if task == "app" and model_type == "resnet":
        train_application_classification_resnet_model(data_path, model_path)
    elif task == "traffic" and model_type == "resnet":
        train_traffic_classification_resnet_model(data_path, model_path)
    elif task == "app" and model_type == "cnn":
        train_application_classification_cnn_model(data_path, model_path)
    elif task == "traffic" and model_type == "cnn":
        train_traffic_classification_cnn_model(data_path, model_path)
    else:
        exit("Not Support")
    message = 'Training of {} model for {} classification has been completed successfully'.format(model_type,task)
    return {"Result": message}


def inference(pcap_file, model_path, model_type, task, gpu):
    if task == "app" and model_type == "resnet":
        model = load_application_classification_resnet_model(
            model_path, gpu=gpu)
    elif task == "traffic" and model_type == "resnet":
        model = load_traffic_classification_resnet_model(model_path, gpu=gpu)
    elif task == "app" and model_type == "cnn":
        model = load_application_classification_cnn_model(model_path, gpu=gpu)
    elif task == "traffic" and model_type == "cnn":
        model = load_traffic_classification_cnn_model(model_path, gpu=gpu)
    else:
        exit("Not Support")

    result_array = []
    type = ''
    packets = read_pcap("pcap_file", BytesIO(pcap_file))
    for i, packet in enumerate(packets):
        arr = transform_packet(packet)
        if arr is not None:
            y_pred = F.log_softmax(
                model(torch.Tensor(arr.todense().tolist())), dim=1)
            y_hat = torch.argmax(y_pred, dim=1)
            result_array.append(int(y_hat))
            print(y_hat)
    results = np.array(result_array)
    values,counts = np.unique(results, return_counts=True)
    if task == "app":
        type = ID_TO_APP.get(int(values[counts.argmax()]))
    elif task == "traffic":
        type = ID_TO_TRAFFIC.get(int(values[counts.argmax()]))
    return {"label": type}

