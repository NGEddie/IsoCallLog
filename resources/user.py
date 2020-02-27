from flask_jwt_extended import jwt_required
from flask_restful import Resource, reqparse
from werkzeug.security import safe_str_cmp
from pymongo import errors as pymongo_errors
from models.user import UserModel


_user_parser = reqparse.RequestParser()
_user_parser.add_argument(
    "name", type=str, required=True, help="name is required", trim=True
)
_user_parser.add_argument(
    "email", type=str, required=True, help="email is required", trim=True
)
_user_parser.add_argument(
    "password", type=str, required=True, help="Password is requred", trim=True
)


class User(Resource):
    @classmethod
    def get(cls, user_id):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"status": "fail", "msg": "User not found"}, 404
        return {"status": "success", "msg": user.json()}


class UserSignup(Resource):
    def post(self):
        data = _user_parser.parse_args()
        try:
            if UserModel.find_by_email(data["email"]):
                return (
                    {
                        "status": "fail",
                        "msg": f"User exists with that email ({data['email']})",
                    },
                    400,
                )

            user = UserModel(**data).save()
            print(user)
            return {
                "status": "success",
                "msg": f"User Created: {user.json()}",
            }
        except ValueError as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return (
                {"status": "fail", "msg": f"Server Error: {str(error)}"},
                500,
            )
        except Exception as e:
            return {"status": "fail", "msg": str(e)}, 500

