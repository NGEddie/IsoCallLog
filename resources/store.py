from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_claims
from pymongo import errors as pymodm_errors

from models.store import StoreModel

_store_parser = reqparse.RequestParser()
_store_parser.add_argument("store", type=str, trim=True)


class Store(Resource):
    @classmethod
    def get(cls, site):
        try:
            store = StoreModel.find_by_site(site)
            if not store:
                return ({"status": "fail", "msg": "Store not found"}, 404)

                return {"status": "success", "msg": store.json()}
        except pymodm_errors.OperationFailure as error:
            return {"status": "fail", "msg": f"Database error - {str(error)}"}, 500

    @classmethod
    @jwt_required
    def post(cls, site):
        try:
            store = StoreModel.find_by_site(site)
            print(store)
            if store:
                return {"status": "fail", "msg": f"Store Already Exists - {store.json()}"}

            data = _store_parser.parse_args()
            newStore = StoreModel(site, **data).save()
            return {'status': 'success', 'msg': newStore.json()}

        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymodm_errors.OperationFailure as error:
            return ({"status": "fail", "msg": f"Server Error: {str(error)}"}, 500)
        except Exception as e:
            return ({"status": "fail", "error": {"type": str(type(e)), "msg": str(e)}}, 500)
