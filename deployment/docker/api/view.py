from flask import Flask, jsonify, request
import os
import main
import json
api_port = os.environ.get("API_PORT","10000")

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

### Common Endpoints ###


@app.route('/version', methods=['GET'])
def version():
    res = jsonify(main.version())
    res.status_code = 200
    return res


@app.route('/health', methods=['GET'])
def health():
    health_status = main.health()
    if health_status:
        res = jsonify(status="healthy")
        res.status_code = 200
    else:
        res = jsonify(status="unhealthy")
        res.status_code = 500
    return res


@app.route('/v2/api-export', methods=['GET'])
def apiexport():
    res = jsonify(main.apiexport())
    res.status_code = 200
    return res

### API ###


@app.route('/v2/preprocess', methods=['POST'])
def preprocess():
    string = main.preprocess()
    res = jsonify(string)
    if json.loads(string)["Result"] == "Pre-processing completed successfully" : res.status_code = 200
    else: res.status_code = 500
    return res


@app.route('/v2/create-train-test-set', methods=['POST'])
def create_train_test_set():
    string = main.create_train_test_set()
    res = jsonify(string)
    if json.loads(string)["Result"] == "Successfully created" : res.status_code = 200
    else: res.status_code = 500
    return res

@app.route('/v2/train', methods=['POST'])
def train():
    content_type = request.headers.get('Content-Type')
    if not(content_type == 'application/json'):
        res = jsonify ('Content-Type not supported!')
        res.status_code = 400
        return res
    string = main.train(request.json)
    res = jsonify(string)
    model_type = request.json['model_type']
    task = request.json['task']
    returnSentence = 'Training of {} model for {} classification has been completed successfully'.format(model_type,task)
    if json.loads(string)["Result"] ==  returnSentence : res.status_code = 200
    else: res.status_code = 500
    return res


@app.route('/v2/cnn-inference-app', methods=['POST'])
def cnn_inference_app():
    pcap_file = request.files.get("pcap_file")
    string = main.cnn_inference_app(pcap_file).text
    res = jsonify(string)
    res.status_code = 200
    return res 

@app.route('/v2/cnn-inference-traffic', methods=['POST'])
def cnn_inference_traffic():
    pcap_file = request.files.get("pcap_file")
    string = main.cnn_inference_traffic(pcap_file).text
    res = jsonify(string)
    res.status_code = 200
    return res 

@app.route('/v2/resnet-inference-app', methods=['POST'])
def resnet_inference_app():
    pcap_file = request.files.get("pcap_file")
    string = main.resnet_inference_app(pcap_file).text
    res = jsonify(string)
    res.status_code = 200
    return res 

@app.route('/v2/resnet-inference-traffic', methods=['POST'])
def resnet_inference_traffic():
    pcap_file = request.files.get("pcap_file")
    string = main.resnet_inference_traffic(pcap_file).text
    res = jsonify(string)
    res.status_code = 200
    return res 

### MAIN ###

if __name__ == "__main__":
    #port = int(os.environ.get('API_PORT'))
    port = 10000
    app.run(debug=True, host='0.0.0.0', port=api_port)
