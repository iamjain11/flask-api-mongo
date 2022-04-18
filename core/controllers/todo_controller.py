from flask import jsonify, request
from bson import ObjectId
from datetime import datetime, timedelta
import sys


from ...app import app, logger, db
from .validate_user import tokenReq


@app.route('/todos', methods=['POST'])
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

