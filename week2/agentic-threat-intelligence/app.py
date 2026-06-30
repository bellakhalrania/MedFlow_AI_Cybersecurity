from flask import Flask, jsonify

app = Flask(__name__)


@app.after_request
def _add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.route("/", methods=["GET"])
def status():
    return jsonify({"status": "running"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
