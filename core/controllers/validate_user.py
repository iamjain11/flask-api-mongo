from functools import wraps
from flask import jsonify, request
secret = "***************"

def tokenReq(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "Authorization" in request.headers:
            token = request.headers["Authorization"]
            try:
                user_details = jwt.decode(token, secret, algorithms="HS256")
                request.token = user_details
            except Exception as err:
                return jsonify({"status": "fail", "message": "unauthorized"}), 401
            return f(*args, **kwargs)
        else:
            return jsonify({"status": "fail", "message": "unauthorized"}), 401
    return decorated