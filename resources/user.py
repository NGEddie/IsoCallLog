from datetime import timedelta
from flask_jwt_extended import (jwt_required, create_access_token,
                                create_refresh_token, get_jwt_claims)
from flask_restful import Resource, reqparse
from pymongo import errors as pymongo_errors
from pymodm import errors as pymodm_errors
from cerberus import Validator
import bcrypt
import re

from models.user import UserModel
from settings import (USER_PASSWORD_MINLENGTH, SALT_ROUNDS, ROLES,
                      DEFAULT_ROLE, JWT_EXPIRATION, EMAIL_PATTERN, validString)


def isEmail(field, value, error):
    if value and not re.match(EMAIL_PATTERN, value):
        error(field, "Invalid Email")


def check_user_exists(username, email):
    if UserModel.find_by_username(username) or UserModel.find_by_email(email):
        return True
    return False


def validate_user(user):
    user_schema = Validator(
        {
            "username": {
                "type": "string",
                "check_with": validString,
                "nullable": True
            },
            "firstName": {
                "type": "string",
                "nullable": True,
                "check_with": validString
            },
            "lastName": {
                "type": "string",
                "nullable": True,
                "check_with": validString
            },
            "email": {
                "type": "string",
                "nullable": True,
                "check_with": isEmail
            },
            "password": {
                "type": "string",
                "minlength": USER_PASSWORD_MINLENGTH,
                "nullable": True
            },
            "role": {
                "type": "string",
                "allowed": ROLES,
                "default": DEFAULT_ROLE,
                "nullable": True
            },
            "initials": {
                "type": "string",
                "nullable": True
            }
        },
        purge_unknown=True)

    if user_schema.validate(user):
        return user_schema.normalized(user)

    raise ValueError({'User': user['username'], 'msg': user_schema.errors})


def encrypt_password(plain_password):
    return bcrypt.hashpw(plain_password.encode("utf-8"),
                         bcrypt.gensalt(SALT_ROUNDS)).decode()


def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8"),
                          hashed_password.encode("utf-8"))


_user_parser = reqparse.RequestParser()
_user_parser.add_argument("username")
_user_parser.add_argument("firstName")
_user_parser.add_argument("lastName")
_user_parser.add_argument("email")
_user_parser.add_argument("password")
_user_parser.add_argument("role")
_user_parser.add_argument("initials")
_user_parser.add_argument("counter")


class User(Resource):
    @classmethod
    @jwt_required
    def get(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to view users"
            }, 403)

        user = UserModel.find_by_username(username)
        if not user:
            return ({"status": "fail", "msg": "User not found"}, 404)

        return {"status": "success", "msg": user.json()}

    @classmethod
    @jwt_required
    def put(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to edit users"
            }, 403)

        user = UserModel.find_by_username(username)
        if not user:
            return {"status": "fail", "msg": "User not found"}, 404

        data = validate_user(_user_parser.parse_args())

        try:
            for field, value in data.items():
                if value:
                    setattr(user, field, value)

            user.update_user()
            return {"status": "success", "msg": f"User updated: {user.json()}"}

        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({
                "status": "fail",
                "msg": f"Server Error: {str(error)}"
            }, 500)
        except Exception as e:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(e)),
                    "msg": str(e)
                }
            }, 500)

    @classmethod
    @jwt_required
    def delete(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to delete users"
            }, 403)

        user = UserModel.find_by_id(username)
        if not user:
            return ({"status": "fail", "msg": "User not found"}, 404)

        try:
            user.delete_from_db()
            return {
                "status": "success",
                "msg": f"User ({user.username}) deleted"
            }
        except Exception as e:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(e)),
                    "msg": str(e)
                }
            }, 500)


class UserSignup(Resource):
    @jwt_required
    def post(self):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to create users"
            }, 403)

        data = validate_user(_user_parser.parse_args())

        try:
            if check_user_exists(data["username"], data["email"]):
                return ({
                    "status":
                    "fail",
                    "msg":
                    f"User already exists ({data['username']}, {data['email']})"
                }, 400)

            data["password"] = encrypt_password(data['password'])
            user = UserModel(**data).update_user()

            return {"status": "success", "msg": f"User Created: {user.json()}"}
        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({
                "status": "fail",
                "msg": f"Server Error: {str(error)}"
            }, 500)
        except Exception as e:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(e)),
                    "msg": str(e)
                }
            }, 500)


class Users(Resource):
    @jwt_required
    def post(self):
        try:
            if not get_jwt_claims()["is_Auth"]:
                return ({
                    "status": "fail",
                    "msg": "Not authorised to create users"
                }, 403)

            users_parser = reqparse.RequestParser()
            users_parser.add_argument('users', type=dict, action='append')

            data = users_parser.parse_args()
            validated_users = []

            for user in data['users']:
                validated_user = validate_user(user)
                if not validated_user:
                    return {
                        'status': 'fail',
                        'msg': f'User: ({user}) not valid'
                    }, 400

                if check_user_exists(validated_user["username"],
                                     validated_user["email"]):
                    return ({
                        "status":
                        "fail",
                        "msg":
                        f"User already exists ({validated_user['username']}, {validated_user['email']})"
                    }, 400)

                validated_user['password'] = encrypt_password(
                    validated_user['password'])

                validated_users.append(validated_user)

            saved_users = UserModel.update_many(validated_users)

            return {'status': 'success', 'msg': {'users created': saved_users}}
        except pymongo_errors.BulkWriteError as error:
            print(error._error_labels)
            return {
                'status': 'fail',
                'msg': {
                    'type':
                    str(type(error)),
                    'error':
                    str(error),
                    'errmsg': [
                        errorDetails['errmsg']
                        for errorDetails in error.details['writeErrors']
                    ]
                }
            }, 400
        except Exception as error:
            return {'status': 'fail', 'msg': str(error)}, 400


class UserLogin(Resource):
    def post(self):
        data = validate_user(_user_parser.parse_args())
        user = UserModel.find_by_username(data["username"])

        if not user or not check_password(data["password"], user.password):
            return {"status": "fail", "msg": "Invalid Login Details"}, 401

        expires_in = timedelta(seconds=JWT_EXPIRATION)
        access_token = create_access_token(identity=str(user._id),
                                           fresh=True,
                                           expires_delta=expires_in)
        refresh_token = create_refresh_token(str(user._id))

        return {
            "status": "success",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "username": user.username,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "initials": user.initials,
            "counter": user.counter
        }
