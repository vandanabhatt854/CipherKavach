"""Local Flask interface for CipherKavach."""

from __future__ import annotations

import os
import tempfile
from io import BytesIO
from pathlib import Path

from flask import Flask, abort, after_this_request, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from cipherkavach_crypto import (
    CipherKavachError,
    decrypt_bytes,
    encrypt_bytes,
)

MAX_FILE_SIZE = int(os.environ.get("CIPHERKAVACH_MAX_FILE_SIZE", 50 * 1024 * 1024))
MAX_PASSWORD_LENGTH = 1024


def _limit_label(size: int) -> str:
    if size % (1024 * 1024) == 0:
        return f"{size // (1024 * 1024)} MB"
    if size % 1024 == 0:
        return f"{size // 1024} KB"
    return f"{size} bytes"


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        MAX_FILE_SIZE=MAX_FILE_SIZE,
        HOSTED=os.environ.get("CIPHERKAVACH_HOSTED") == "1",
        # Leave room for multipart headers, then enforce the exact file size below.
        MAX_CONTENT_LENGTH=MAX_FILE_SIZE + 128 * 1024,
        TEMP_DIR=None,
    )
    if test_config:
        app.config.update(test_config)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify(error=f"The upload exceeds the {_limit_label(app.config['MAX_FILE_SIZE'])} limit."), 413
        return "Upload exceeds the configured file-size limit.", 413

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            max_file_size=app.config["MAX_FILE_SIZE"],
            hosted=app.config["HOSTED"],
        )

    @app.post("/api/<action>")
    def process_file(action: str):
        if action not in {"encrypt", "decrypt"}:
            abort(404)
        upload = request.files.get("file")
        password = request.form.get("password", "")
        if upload is None or not upload.filename:
            return jsonify(error="Choose a file to continue."), 400
        if not password:
            return jsonify(error="Enter your password to continue."), 400
        if len(password) > MAX_PASSWORD_LENGTH:
            return jsonify(error=f"Passwords must be {MAX_PASSWORD_LENGTH} characters or fewer."), 400
        if action == "encrypt" and request.form.get("confirm_password", "") != password:
            return jsonify(error="The password confirmation does not match."), 400

        original_name = secure_filename(upload.filename) or "download"
        temp_dir = tempfile.TemporaryDirectory(dir=app.config.get("TEMP_DIR"))
        try:
            input_path = Path(temp_dir.name) / "upload.bin"
            upload.save(input_path)
            size = input_path.stat().st_size
            if size > app.config["MAX_FILE_SIZE"]:
                temp_dir.cleanup()
                return jsonify(error=f"The file exceeds the {_limit_label(app.config['MAX_FILE_SIZE'])} limit."), 413

            source = input_path.read_bytes()
            if action == "encrypt":
                result = encrypt_bytes(source, password)
                download_name = f"{original_name}.ckv"
            else:
                result = decrypt_bytes(source, password)
                download_name = original_name[:-4] if original_name.lower().endswith(".ckv") else f"{original_name}.decrypted"
            temp_dir.cleanup()
            return send_file(BytesIO(result), as_attachment=True, download_name=download_name, mimetype="application/octet-stream", max_age=0)
        except CipherKavachError as exc:
            temp_dir.cleanup()
            return jsonify(error=str(exc)), 400
        except OSError:
            temp_dir.cleanup()
            app.logger.warning("A file operation failed during %s.", action)
            return jsonify(error="The file could not be processed. Check the file and try again."), 500
        except Exception:
            temp_dir.cleanup()
            app.logger.exception("Unexpected failure while processing a %s request.", action)
            return jsonify(error="The file could not be processed. Please try again."), 500

    return app


app = create_app()


if __name__ == "__main__":
    # Loopback only; do not expose this development server on the network.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
