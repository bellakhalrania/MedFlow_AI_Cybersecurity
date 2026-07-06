import logging
from time import perf_counter

from flask import Flask, jsonify, request
from werkzeug.exceptions import BadRequest, HTTPException

from config import config
from investigation_service import run_investigation

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

config.validate()

@app.after_request
def _add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response


@app.before_request
def _log_incoming_request():
    logger.info(
        "Incoming request method=%s path=%s remote_addr=%s",
        request.method,
        request.path,
        request.remote_addr,
    )


@app.errorhandler(HTTPException)
def _handle_http_exception(error):
    logger.warning("HTTP error status=%s path=%s detail=%s", error.code, request.path, error.description)
    return jsonify({"error": error.description}), error.code


@app.errorhandler(Exception)
def _handle_unexpected_exception(error):
    logger.exception("Unhandled server error path=%s", request.path)
    return jsonify({"error": "Internal server error"}), 500


@app.route("/", methods=["GET"])
def status():
    return jsonify({"status": "running"})


@app.route("/investigate", methods=["POST"])
def investigate():
    if not request.data:
        logger.warning("Rejecting request with empty body path=%s", request.path)
        return jsonify({"error": "Request body is empty"}), 400

    try:
        payload = request.get_json(force=False, silent=False)
    except BadRequest:
        logger.warning("Rejecting request with invalid JSON path=%s", request.path)
        return jsonify({"error": "Invalid JSON"}), 400

    if isinstance(payload, list):
        raw_events = payload
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        raw_events = payload["events"]
    else:
        logger.warning("Rejecting request with invalid events payload path=%s", request.path)
        return jsonify({"error": "Expected a JSON array of events or an object with an 'events' array"}), 400

    if not raw_events:
        logger.warning("Rejecting request with empty events list path=%s", request.path)
        return jsonify({"error": "Events list cannot be empty"}), 400

    if not all(isinstance(event, dict) for event in raw_events):
        logger.warning("Rejecting request with non-object events count=%d path=%s", len(raw_events), request.path)
        return jsonify({"error": "Each event must be a JSON object"}), 400

    start_time = perf_counter()
    try:
        logger.info("Received %d events", len(raw_events))
        logger.info("Workflow execution start")
        final_state = run_investigation(raw_events)
        duration = perf_counter() - start_time
        logger.info("Workflow execution end duration=%.3fs", duration)
    except Exception:
        duration = perf_counter() - start_time
        logger.exception("Investigation workflow failed duration=%.3fs", duration)
        return jsonify({"error": "Workflow execution failed"}), 500

    return jsonify(final_state), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    # app.run(host="127.0.0.1", port=5000)
