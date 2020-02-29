from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import User, UserSignup, UserLogin
from models.user import UserModel
from settings import jwt_secret_key, jwt_expiration, roles


app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = jwt_secret_key
app.config["PROPAGATE_EXCEPTIONS"] = True

api = Api(app)
jwt = JWTManager(app)


@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    user = UserModel.find_by_id(identity)
    if user.role == roles[0]:
        return {"is_Auth": True}
    return {"is_Auth": False}


@jwt.expired_token_loader
def expired_token_callback():
    return (
        jsonify({"description": "The token has expired", "error": "token expired"}),
        401,
    )


api.add_resource(User, "/user/<string:username>")
api.add_resource(UserLogin, "/login")
api.add_resource(UserSignup, "/createuser")

if __name__ == "__main__":
    app.run(port=5000, debug=True)
