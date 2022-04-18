import jwt
from datetime import datetime, timedelta
import sys

from ...app import logger, db, app, jsonify, request,bcrypt
secret = "***************"

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
