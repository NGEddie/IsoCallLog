from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from resources.user import User, UserSignup
from settings import jwt_secret_key, jwt_expiration

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = jwt_secret_key
app.config["JWT_EXPIRATION_DELTA"] = jwt_expiration
app.config["PROPAGATE_EXCEPTIONS"] = True

api = Api(app)
jwt = JWTManager(app)

api.add_resource(User, "/user/<string:user_id>")
api.add_resource(UserSignup, "/createuser")

if __name__ == "__main__":
    app.run(port=5000, debug=True)
