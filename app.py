from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager

from models.user import UserModel

from resources.user import User, UserSignup, UserLogin, Users
from resources.store import Store, Stores
from resources.iso_call import NewCall, Call, AuthCode

from settings import JWT_SECRET_KEY, ROLES

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["PROPAGATE_EXCEPTIONS"] = True

api = Api(app)
jwt = JWTManager(app)


@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    user = UserModel.find_by_id(identity)
    if user.role == ROLES[4]:
        return {"is_Auth": True}
    return {"is_Auth": False}


@jwt.expired_token_loader
def expired_token_callback():
    return (
        jsonify({
            "description": "The token has expired",
            "error": "token expired"
        }),
        401,
    )


api.add_resource(User, "/user/<string:username>")
api.add_resource(UserLogin, "/login")
api.add_resource(UserSignup, "/createuser")
api.add_resource(Store, "/store/<string:site>")
api.add_resource(NewCall, "/createcall")
api.add_resource(Call, "/callID/<string:id>")
api.add_resource(AuthCode, "/auth_code/<string:auth_code>")
api.add_resource(Users, "/users")
api.add_resource(Stores, "/stores")

if __name__ == "__main__":
    app.run(port=5000, debug=True)
