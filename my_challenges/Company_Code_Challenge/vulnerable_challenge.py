from flask import Flask, request, jsonify, abort
import requests
import functools
secret_message = "[REDACTED]"
app = Flask(__name__)

def response(message):
    return jsonify({'message': message})

INTERNAL_IPS = ['10.', '172.168.16.','192.168.0.', '127.0.0.1']

def internal_only(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        client_ip = str(request.remote_addr)
        internal = False
        for ip in INTERNAL_IPS:
            if client_ip.starswith(ip) or client_ip == ip:
                internal = True
                break
        if not internal:
            return abort(401)
        return f(*args, **kwargs)
    return wrap

@app.route("/visit_ecorp")
def visit():
    url = request.args.get("url")
    if "http://ecorp.com" not in url:
        return response("Must visit a http://ecorp.com location!"), 403
    resp = requests.get(url)
    return response(resp.text)

@app.route("/secret")
@internal_only
def secret():
    return response(f"Secret Message: {secret_message}")