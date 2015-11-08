import time
from flask import Flask, request, send_from_directory, Response

app = Flask(__name__, static_url_path='/static')


@app.route('/logs')
def logs():
    return send_from_directory(app.static_folder, 'dnslog.txt')


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def dns_name(path):
    if path != 'logs':
        with open(app.static_folder + "/dnslog.txt", "a") as myfile:
            myfile.write("\n" + time.strftime("%d/%m/%Y %H:%M:%S") + " -- " + request.url_root)
    return request.url_root


if __name__ == "__main__":
    app.run(port=5002, host='127.0.0.2')
