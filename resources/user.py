from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_claims
from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from pymongo import errors as pymongo_errors
from pymodm import errors as pymodm_errors
from cerberus import Validator
import bcrypt

from models.user import UserModel
from settings import user_password_minlength


def validate_password(plain_password):
    password_schema = Validator({"password": {"type": "string", "minlength": user_password_minlength}})
    if password_schema.validate({"password": plain_password}):
        return plain_password
    raise ValueError(password_schema.errors)


def check_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


_user_parser = reqparse.RequestParser()
_user_parser.add_argument("username", type=str, required=True, help="username is required", trim=True)
_user_parser.add_argument("password", type=validate_password, required=True, trim=True)


class User(Resource):
    @classmethod
    @jwt_required
    def get(cls, username):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to view users"}, 403)

        user = UserModel.find_by_username(username)
        if not user:
            return {"status": "fail", "msg": "User not found"}, 404

        return {"status": "success", "msg": user.json()}


class UserSignup(Resource):
    @jwt_required
    def post(self):
        if not get_jwt_claims()["is_Auth"]:
            return ({"status": "fail", "msg": "Not authorised to create users"}, 403)

        _user_parser.add_argument("email", type=str, required=True, help="email is required", trim=True)

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

        access_token = create_access_token(identity=str(user._id), fresh=True)
        refresh_token = create_refresh_token(str(user._id))

        return {"status": "success", "access_token": access_token, "refresh_token": refresh_token}
