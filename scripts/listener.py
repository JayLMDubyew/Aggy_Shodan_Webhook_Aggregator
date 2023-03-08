from logging.config import dictConfig
from pathlib import Path

from flask import Flask, request, Response, render_template

import webhook_processing

dictConfig(
    {
        "version": 1,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: \n %(message)s",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "default",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": "shodan_webhook_listener.log",
                "formatter": "default",
            },
        },
        "root": {"level": "INFO", "handlers": ["console", "file"]},
    }
)

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/webhook', methods=['POST'])
def respond():
    if not request.json:
        return Response(status=400)
    app.logger.debug(request.json)
    app.logger.info(request.host)
    req = request.get_json()
    alert_type = req['_shodan']['module']
    if alert_type == "database":
        webhook_processing.process_open_db(req)
    else:
        webhook_processing.process_request_not_db(req)

    return Response(status=200)


if __name__ == '__main__':
    from waitress import serve
    from configparser import ConfigParser

    config_info = ConfigParser()
    current_file_path = Path(__file__).resolve().parents[1]
    init = Path(current_file_path, 'config.ini')
    config_info.read(init)

    addr = config_info.get('listener_config', 'host')
    listen_port = config_info.getint('listener_config', 'port')
    serve(app, host=addr, port=listen_port)
