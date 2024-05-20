import os
import yaml
import requests

ml = os.environ.get("ML_HOST", "localhost")
ml_port = os.environ.get("ML_PORT","10111")


def version():
    headers = ['enabler', 'version']
    try:
        data = [os.environ['ENABLER_NAME'], os.environ['ENABLER_VERSION']]
    except:
        data = ["Traffic classification", "2.0.0"]
    return dict(zip(headers, data))


def health():
    health_status = True
    if (requests.get('http://{}:{}/health'.format(ml, ml_port)).status_code != 200 or
            requests.get('http://{}:{}/health'.format(ml, ml_port)).status_code != 200):
        health_status = False
    return health_status


def apiexport():
    f = open('openapi.yaml')
    data = yaml.load(f, Loader=yaml.Loader)
    return data


def preprocess():
    url = 'http://{}:{}/preprocess'.format(ml, ml_port)
    data = requests.post(url).text
    return data


def create_train_test_set():
    url = 'http://{}:{}/create_train_test_set'.format(ml, ml_port)
    data = requests.post(url).text
    return data


def train(json):
    url = 'http://{}:{}/train'.format(ml, ml_port)
    data = requests.post(url, json=json).text
    return data


def cnn_inference_app(pcap_file):
    url = 'http://{}:{}/cnn_inference_app'.format(ml, ml_port)
    data = requests.post(url, data=pcap_file, headers={'Content-Type': 'application/octet-stream'})
    return data


def cnn_inference_traffic(pcap_file):
    url = 'http://{}:{}/cnn_inference_traffic'.format(ml, ml_port)
    data = requests.post(url, data=pcap_file, headers={'Content-Type': 'application/octet-stream'})
    return data


def resnet_inference_app(pcap_file):
    url = 'http://{}:{}/resnet_inference_app'.format(ml, ml_port)
    data = requests.post(url, data=pcap_file, headers={'Content-Type': 'application/octet-stream'})
    return data


def resnet_inference_traffic(pcap_file):
    url = 'http://{}:{}/resnet_inference_traffic'.format(ml, ml_port)
    data = requests.post(url, data=pcap_file, headers={'Content-Type': 'application/octet-stream'})
    return data
