import os

from flask import Flask, send_from_directory
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple


HOME_ROOT = os.path.abspath(os.path.dirname(__file__))


def create_home_app():
    app = Flask(__name__, static_folder=None)

    @app.route("/")
    def home():
        return send_from_directory(HOME_ROOT, "home.html")

    @app.route("/home.html")
    def home_html():
        return send_from_directory(HOME_ROOT, "home.html")

    @app.route("/home.css")
    def home_css():
        return send_from_directory(HOME_ROOT, "home.css")

    @app.route("/home.js")
    def home_js():
        return send_from_directory(HOME_ROOT, "home.js")

    return app


# Ensure the tool app uses root routes while mounted under /tools/ECA_Tools.
os.environ["TOOLS_PREFIX"] = "/"

from Tools.ECA_Tools.WebApp.app import app as eca_app


home_app = create_home_app()
application = DispatcherMiddleware(home_app, {"/tools/ECA_Tools": eca_app})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    run_simple("0.0.0.0", port, application)
