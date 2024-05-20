from flask import Flask, jsonify, request
import os
import main

app = Flask(__name__)
ml_port = os.environ.get("ML_PORT","10111")
base_folder = os.environ.get("BASE_FOLDER","../../../documentation/examples/ML_model")


@app.route('/health', methods=['GET'])
def health():
    res = jsonify(status="healthy")
    res.status_code = 200
    return res


@app.route('/preprocess', methods=['POST'])
def preprocess():
    # Path to the directory for persisting preprocessed files
    source = base_folder + "/data"
    # Path to the directory for persisting preprocessed files
    target = base_folder + "/preprocessed"
    njob = 1  # int(os.environ['NJOB'])  # Num of executors
    res = main.preprocess(source, target, njob)
    return res

@app.route('/create_train_test_set', methods=['POST'])
def create_train_test_set():
    # Path to the directory for persisting preprocessed files
    source = base_folder + "/preprocessed"
    target = base_folder + "/target"
    test_size = 0.2
    under_sampling = False
    res = main.create_train_test_set(source, target, test_size, under_sampling)
    return res


@app.route('/train', methods=['POST'])
def train():
    # !LATER ON EVALUATE WHICH ARGS ARE PASSED VIA BODY INSTEAD ENV VARS
    content_type = request.headers.get('Content-Type')
    if not (content_type == 'application/json'):
        return 'Content-Type not supported!'
    request_data = request.get_json()
    model_type = request_data['model_type']
    task = request_data['task']
    if not (model_type) or not (task):
        return 'Error in json body'

    # Training data dir path containing parquet files
    data_path = base_folder + "/target"
    if task == "app" and model_type == "resnet":
        model_path = base_folder + "/model/working/app_classification_resnet.model"
    elif task == "traffic" and model_type == "resnet":
        model_path = base_folder + "/model/working/traffic_classification_resnet.model"
    elif task == "app" and model_type == "cnn":
        model_path = base_folder + "/model/working/app_classification_cnn.model"
    elif task == "traffic" and model_type == "cnn":
        model_path = base_folder + "/model/working/traffic_classification_cnn.model"
    return main.train(data_path, model_path, model_type, task)


@app.route('/cnn_inference_app', methods=['POST'])
def cnn_inference_app():
    pcap_file = request.data
    model_path = base_folder + "/model/working/app_classification_cnn.model"
    model_type = "cnn"
    task = "app"
    gpu = False  # TO UPDATE
    res = main.inference(pcap_file, model_path, model_type, task, gpu)
    return str(res)


@app.route('/cnn_inference_traffic', methods=['POST'])
def cnn_inference_traffic():
    pcap_file = request.data
    model_path = base_folder + "/model/working/traffic_classification_cnn.model"
    model_type = "cnn"
    task = "traffic"
    gpu = False  # TO UPDATE
    res = main.inference(pcap_file, model_path, model_type, task, gpu)
    return str(res)
    

@app.route('/resnet_inference_app', methods=['POST'])
def resnet_inference_app():
    pcap_file = request.data
    model_path = base_folder + "/model/working/app_classification_resnet.model"
    model_type = "resnet"
    task = "app"
    gpu = False  # TO UPDATE
    res = main.inference(pcap_file, model_path, model_type, task, gpu)
    return str(res)


@app.route('/resnet_inference_traffic', methods=['POST'])
def resnet_inference_traffic():
    pcap_file = request.data
    model_path = base_folder + "/model/working/traffic_classification_resnet.model"
    model_type = "resnet"
    task = "traffic"
    gpu = False  # TO UPDATE
    res = main.inference(pcap_file, model_path, model_type, task, gpu)
    return str(res)
### MAIN ###


if __name__ == "__main__":
    #port = int(os.environ.get('ML_PORT'))
    app.run(debug=True, host='0.0.0.0', port=ml_port)
