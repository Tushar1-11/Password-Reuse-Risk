from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from analyzer import PasswordReuseAnalyzer

BASE_DIR = Path(__file__).resolve().parent


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        DATABASE=os.environ.get("DATABASE", os.path.join(app.instance_path, "password_risk.sqlite3")),
        SECRET_FILE=os.environ.get("SECRET_FILE", os.path.join(app.instance_path, "fingerprint.key")),
        MODEL_DIR=os.path.join(BASE_DIR, "model"),
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    analyzer = PasswordReuseAnalyzer(
        app.config["DATABASE"],
        app.config["SECRET_FILE"],
        app.config["MODEL_DIR"],
    )
    analyzer.initialize()
    app.extensions["reuse_analyzer"] = analyzer

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "ml_enabled": analyzer.model_available,
            "message": "ANN model loaded." if analyzer.model_available else "ANN model not found. Run train_password_reuse_ann.py first.",
        })

    @app.get("/api/dashboard")
    def dashboard():
        return jsonify(analyzer.dashboard())

    @app.post("/api/entries")
    def add_entry():
        payload = request.get_json(silent=True) or {}
        platform = str(payload.get("platform", ""))
        password = payload.get("password")
        sensitivity = str(payload.get("sensitivity", "standard"))
        try:
            result = analyzer.add_entry(platform, password, sensitivity)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(result), 201

    @app.delete("/api/entries/<int:entry_id>")
    def delete_entry(entry_id: int):
        if not analyzer.delete_entry(entry_id):
            return jsonify({"error": "Account record not found."}), 404
        return "", 204

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
