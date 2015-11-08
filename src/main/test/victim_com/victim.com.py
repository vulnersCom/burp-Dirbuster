import urllib2
from flask import Flask, Response, render_template, redirect, url_for, send_from_directory, request

app = Flask(__name__, static_url_path='/static')


@app.route("/")
@app.route("/index")
def index():
    return render_template('index.html')


@app.route("/csrf_page")
def csrf_page():
    return render_template('csrf_page.html')


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')


@app.route('/token_page', methods=['GET', 'POST'])
def token_page():
    token = request.form.get('token')
    if token is None or token != '123qweasd456erttdfg':
        return Response('{"status": "To pass this form you should enter Valid CSRF Token", "TOKEN":"123qweasd456erttdfg"}', mimetype='text/json')
    else:
        return render_template('token_page.html')


@app.route('/ssrf_page')
def ssrf_page():
    serverUrl = request.args.get('serverUrl')
    if serverUrl is not None:
        return urllib2.urlopen(serverUrl).read()
    else:
        return 'Please enter serverUrl to Check'


@app.route('/<path:path>')
def templates(path):
    try:
        return render_template(path)
    except:
        return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(port=5001, host='127.0.0.1')
