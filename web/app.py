"""
API which stores a users Username, Password, and given sentence
using a MongoDB database
"""
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SentencesDatabase
users = db["Users"]


class Register(Resource):
    # Class which registers a User, with a username and password
    def post(self):
        # Get posted data
        postedData = request.get_json()

        # Get the data
        username = postedData["username"]
        password = postedData["password"]

        # hash(password + salt) = kfwkfnwkfnw
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store username and password into db
        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Sentence": "",
            "Tokens": 5
        })

        ret_JSON = {
            "status": 200,
            "message": "Successful API sign up"
        }
        return jsonify(ret_JSON)


def verifyPW(username, password):
    # Verify if user entered correct username + password
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf-8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def countTokens(username):
    # Counts the amount of tokens the user has left
    tokens = users.find({
        "Username": username
    })[0]["Tokens"]
    return tokens


class Store(Resource):
    # Stores the users [username, password, and entered sentence]
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        sentence = postedData["sentence"]

        # Verify the username password match
        correct_pw = verifyPW(username, password)

        if not correct_pw:
            ret_JSON = {
                "status": 302
            }
            return jsonify(ret_JSON)
        # Verify if user has enough tokens
        num_tokens = countTokens(username)

        if num_tokens <= 0:
            ret_JSON = {
                "status": 301
            }
        # Store the sentence, take one token away, and return 200 status
        users.update({
            "Username": username
        }, {
            "$set": {
                "Sentence": sentence,
                "Tokens": num_tokens - 1
            }
        })
        ret_JSON = {
            "status": 200,
            "msg": "Sentence saved"
        }
        return jsonify(ret_JSON)


class Get(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]

        correct_pw = verifyPW(username, password)

        if not correct_pw:
            ret_JSON = {
                "status": 302
            }
            return jsonify(ret_JSON)
        # Verify if user has enough tokens
        num_tokens = countTokens(username)

        if num_tokens <= 0:
            ret_JSON = {
                "status": 301
            }

        # Retrieve the sentence, take one token away, and return 200 status
        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": num_tokens - 1
            }
        })

        sentence = users.find({
            "Username": username
        })[0]["Sentence"]
        ret_JSON = {
            "status": 200,
            "sentence": sentence
        }
        return jsonify(ret_JSON)


api.add_resource(Register, '/register')
api.add_resource(Store, '/store')
api.add_resource(Get, '/get')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
