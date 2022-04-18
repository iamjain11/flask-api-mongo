from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_cors import CORS
from bson import ObjectId
import json
import jwt
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from functools import wraps
import sys
import logging
import os

db_username = os.environ.get('MONGODB_USERNAME') or 'root'
db_password = os.environ.get('MONGODB_PASSWORD')  or '12345'
db_name = os.environ.get('MONGODB_DATABASE_NAME') or 'pymongodb'


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__file__)


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
bcrypt = Bcrypt(app)
secret = "***************"
# uri = "mongodb://root:12345@localhost/?authSource=the_database&authMechanism=SCRAM-SHA-256"
uri = f"mongodb://{db_username}:{db_password}@localhost"


mongo = MongoClient(uri, 27017)

db = mongo[db_name]  # py_api is the name of the db


# class Book(db.Document):
#     pass

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


@app.route('/')
def func():
    return "😺", 200

# get all and insert one


@app.route('/todos', methods=['GET', 'POST'])
def index():
    res = []
    code = 500
    try:
        res = db['todos'].insert_one(request.get_json())
        if res.acknowledged:
            code = 200
            res_data = {"_id": f"{res.inserted_id}"}
        else:
            message = "insert error"
            code = 500
            res_data = {
                "message": "failed to create task",
                "status": code
            }
    except Exception as ee:
        message = str(ee)
        type, value, traceback = sys.exc_info()
        logger.error('failed to get/update task:  %s : %s : %s' %
                     (value, type, traceback))
        res_data = {
            "message": message,
            "status": code
        }
    return jsonify(res_data), code

# get one and update one


@app.route('/delete/<item_id>', methods=['DELETE'])
@tokenReq
def delete_one(item_id):
    data = {}
    code = 500
    message = ""
    try:
        res = db['todos'].delete_one({"_id": ObjectId(item_id)})
        if res:
            message = "Delete successfully"
            code = 201
        else:
            message = "Task not found"
            code = 404

    except Exception as ee:
        message = str(ee)
        type, value, traceback = sys.exc_info()
        logger.error('delete_one : failed to delete task:  %s' % (value))
        data = {
            "message": message,
            "status": code
        }

    return jsonify({"status": code, "message": message, 'data': data}), code

# get one and update one


@app.route('/todos/<item_id>', methods=['GET', 'PUT'])
@tokenReq
def by_id(item_id):
    data = {}
    code = 500
    try:
        if (request.method == 'PUT'):

            todo_data = request.get_json()
            todo_data['modified_by'] = request.token['email']
            todo_data['modified_date'] = datetime.utcnow()

            res = db['todos'].update_one({"_id": ObjectId(item_id)}, {
                                         "$set": todo_data})
            if res:
                message = "updated successfully"
                code = 201

                data = {
                    "message": message,
                    "status": code
                }

            else:
                message = "update failed"
                code = 404
                data = {
                    message,
                    code
                }
        else:
            data = db['todos'].find_one({"_id": ObjectId(item_id)})
            data['_id'] = str(data['_id'])
            if data:
                code = 200
            else:
                message = "not found"
                code = 404
                data = {
                    message,
                    code
                }
    except Exception as ee:
        message = str(ee)
        type, value, traceback = sys.exc_info()
        logger.error('failed to get/update task:  %s' % (value))
        data = {
            "message": message,
            "status": 500
        }

    return jsonify(data), code


@app.route('/signup', methods=['POST'])
def save_user():
    code = 500
    res_data = {}
    try:
        data = request.get_json()
        check = db['users'].find({"email": data['email']})
        if check.count() >= 1:
            code = 401
            res_data = {
                "message": "email is used by other user",
                "status": code
            }
        else:
            # hashing the password so it's not stored in the db as it was
            data['password'] = bcrypt.generate_password_hash(
                data['password']).decode('utf-8')
            data['created'] = datetime.now()

            # this is bad practice since the data is not being checked before insert
            res = db["users"].insert_one(data)
            if res.acknowledged:
                code = 201
                res_data = {
                    "message": "user created successfully",
                    "status": code
                }
    except Exception as ex:
        message = f"{ex}"
        code = 500
        type, value, traceback = sys.exc_info()
        logger.error('failed to get/update task:  %s : %s : %s' %
                     (value, type, traceback))
        res_data = {
            "message": message,
            "status": code
        }
    return jsonify(res_data), code


@app.route('/login', methods=['POST'])
def login():
    res_data = {}
    code = 500
    try:
        data = request.get_json()
        user = db['users'].find_one({"email": f'{data["email"]}'})

        if user:
            user['_id'] = str(user['_id'])
            if user and bcrypt.check_password_hash(user['password'], data['password']):
                time = datetime.utcnow() + timedelta(hours=24)
                token = jwt.encode(
                    {
                        "email": f"{user['email']}",
                        "id": f"{user['_id']}",
                        "exp": time
                    },
                    secret
                )

                del user['password']

                code = 200

                user["token"] = token

                res_data = user

            else:
                code = 401
                res_data = {
                    "message": "invalid username and password",
                    "status": code
                }
        else:
            code = 401
            res_data = {
                "message": "invalid username and password",
                "status": code
            }

    except Exception as ex:
        message = f"{ex}"
        code = 500
        type, value, traceback = sys.exc_info()
        logger.error('failed to get/update task:  %s : %s : %s' %
                     (value, type, traceback))
        res_data = {
            "message": message,
            "status": 500
        }
    return jsonify(res_data), code


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port='8000')
