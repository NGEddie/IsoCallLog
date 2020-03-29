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
from settings import (USER_PASSWORD_MINLENGTH, ROLES, DEFAULT_ROLE,
                      JWT_EXPIRATION, EMAIL_PATTERN, validString)


def isEmail(field, value, error):
    if value and not re.match(EMAIL_PATTERN, value):
        error(field, "Invalid Email")


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
            }
        },
        purge_unknown=True)

    if user_schema.validate(user):
        return user_schema.normalized(user)

    raise ValueError({'User': user['username'], 'msg': user_schema.errors})


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
            if UserModel.find_by_username(
                    data["username"]) or UserModel.find_by_email(
                        data["email"]):
                return ({
                    "status":
                    "fail",
                    "msg":
                    f"User already exists ({data['username']}, {data['email']})"
                }, 400)

            data["password"] = bcrypt.hashpw(data["password"].encode("utf-8"),
                                             bcrypt.gensalt(14)).decode()
            user = UserModel(**data).save()

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
    def post(self):
        try:
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
                validated_users.append(validated_user)
            saved_users = UserModel.update_many(validated_users)
            return {'status': 'success', 'msg': {'Users created': saved_users}}
        except ValueError as error:
            print(error)
            return {'status': 'fail', 'msg': str(error)}, 400
        except Exception as error:
            return str(error)


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
            "refresh_token": refresh_token
        }
