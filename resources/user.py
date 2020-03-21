from datetime import timedelta
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_claims
from flask_restful import Resource, reqparse
from pymongo import errors as pymongo_errors
from pymodm import errors as pymodm_errors
from cerberus import Validator
import bcrypt

from models.user import UserModel
from settings import user_password_minlength, roles, default_role, jwt_expiration


def validate_password(plain_password):
    password_schema = Validator({"password": {"type": "string", "minlength": user_password_minlength}})
    if password_schema.validate({"password": plain_password}):
        return plain_password
    raise ValueError(password_schema.errors)


def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


_user_parser = reqparse.RequestParser()
_user_parser.add_argument("username", type=str, help="username is required", trim=True)
_user_parser.add_argument("password", type=validate_password, trim=True)
_user_parser.add_argument("role", type=str, trim=True, choices=roles, default=default_role)
_user_parser.add_argument("email", type=str, help="email is required", trim=True)


class User(Resource):
    @classmethod
    @jwt_required
    def get(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to view users"}, 403)

        user = UserModel.find_by_username(username)
        if not user:
            return ({"status": "fail", "msg": "User not found"}, 404)

        return {"status": "success", "msg": user.json()}

    @classmethod
    @jwt_required
    def put(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to edit users"}, 403)

        user = UserModel.find_by_username(username)
        if not user:
            return {"status": "fail", "msg": "User not found"}, 404

        data = _user_parser.parse_args()

        try:
            for field, value in data.items():
                if value:
                    setattr(user, field, value)

            user.update_user()
            return {"status": "success", "msg": f"User updated: {user.json()}"}

        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({"status": "fail", "msg": f"Server Error: {str(error)}"}, 500)
        except Exception as e:
            return ({"status": "fail", "error": {"type": str(type(e)), "msg": str(e)}}, 500)

    @classmethod
    @jwt_required
    def delete(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to delete users"}, 403)

        user = UserModel.find_by_id(username)
        if not user:
            return ({"status": "fail", "msg": "User not found"}, 404)

        try:
            user.delete_from_db()
            return {"status": "success", "msg": f"User ({user.username}) deleted"}
        except Exception as e:
            return ({"status": "fail", "error": {"type": str(type(e)), "msg": str(e)}}, 500)


class UserSignup(Resource):
    @jwt_required
    def post(self):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to create users"}, 403)

        data = _user_parser.parse_args()

        try:
            if UserModel.find_by_username(data["username"]) or UserModel.find_by_email(data["email"]):
                return ({"status": "fail", "msg": f"User already exists ({data['username']}, {data['email']})"}, 400)

            data["password"] = bcrypt.hashpw(data["password"].encode("utf-8"), bcrypt.gensalt(14)).decode()
            user = UserModel(**data).save()

            return {"status": "success", "msg": f"User Created: {user.json()}"}
        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({"status": "fail", "msg": f"Server Error: {str(error)}"}, 500)
        except Exception as e:
            return ({"status": "fail", "error": {"type": str(type(e)), "msg": str(e)}}, 500)


class UserLogin(Resource):
    def post(self):
        data = _user_parser.parse_args()
        user = UserModel.find_by_username(data["username"])

        if not user or not check_password(data["password"], user.password):
            return {"status": "fail", "msg": "Invalid Login Details"}, 401

        expires_in = timedelta(seconds=jwt_expiration)
        access_token = create_access_token(identity=str(user._id), fresh=True, expires_delta=expires_in)
        refresh_token = create_refresh_token(str(user._id))

        return {"status": "success", "access_token": access_token, "refresh_token": refresh_token}
