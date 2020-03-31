from flask_restful import Resource, reqparse
from flask_jwt_extended import jwt_required, get_jwt_claims
from pymongo import errors as pymongo_errors
from pymodm import errors as pymodm_errors
from cerberus import Validator

from models.store import StoreModel
from models.user import UserModel

from settings import AREAS, REGIONS

_store_parser = reqparse.RequestParser()
_store_parser.add_argument("store", type=str, trim=True)
_store_parser.add_argument("fpp", type=str, trim=True)
_store_parser.add_argument("region", type=str, trim=True)
_store_parser.add_argument("area", type=str, trim=True)


def validate_store(store):
    store_schema = Validator(
        {
            "site": {
                "type": "integer",
                "min": 3,
                "max": 999
            },
            "fpp": {
                "type": "string"
            },
            "region": {
                "type": "string",
                "allowed": REGIONS
            },
            "area": {
                "type": "string",
                "allowed": AREAS
            }
        },
        purge_unknown=True)

    if store_schema.validate(store):
        return store_schema.normalized(store)

    raise ValueError({'store': store['store'], 'msg': store_schema.error})


class Store(Resource):
    @classmethod
    def get(cls, site):
        try:
            store = StoreModel.find_by_site(site)
            if not store:
                return ({"status": "fail", "msg": "Store not found"}, 404)

            return {"status": "success", "msg": store.json()}
        except pymodm_errors.OperationFailure as error:
            return {
                "status": "fail",
                "msg": f"Database error - {str(error)}"
            }, 500

    @classmethod
    @jwt_required
    def post(cls, site):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to create stores"
            }, 403)

        try:
            store = StoreModel.find_by_site(site)
            if store:
                return ({
                    "status": "fail",
                    "msg": f"Store Already Exists - {store.json()}"
                }, 400)

            data = validate_store(_store_parser.parse_args())

            fpp = UserModel.find_by_username(data['fpp'])
            data['fpp'] = fpp._id
            new_store = StoreModel(site, **data).save()
            return {'status': 'success', 'msg': new_store.json()}

        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({
                "status": "fail",
                "msg": f"Server Error: {str(error)}"
            }, 500)
        except Exception as error:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(error)),
                    "msg": str(error)
                }
            }, 500)

    @classmethod
    @jwt_required
    def put(cls, site):
        if not get_jwt_claims()["is_Auth"]:
            return ({
                "status": "fail",
                "msg": "Not authorised to edit stores"
            }, 403)

        try:
            store = StoreModel.find_by_site(site)
            if not store:
                return {
                    'status': 'fail',
                    'msg': f'Site: {site}, not found'
                }, 404

            data = validate_store(_store_parser.parse_args())

            for field, value in data.items():
                if value:
                    setattr(store, field, value)

            store.update_store()

            return {
                'status': 'success',
                'msg': f'Store updated: {store.json()}'
            }

        except (ValueError, pymodm_errors.ValidationError) as error:
            return {"status": "fail", "msg": str(error)}, 400
        except pymongo_errors.OperationFailure as error:
            return ({
                "status": "fail",
                "msg": f"Server Error: {str(error)}"
            }, 500)
        except Exception as error:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(error)),
                    "msg": str(error)
                }
            }, 500)

    @classmethod
    @jwt_required
    def delete(cls, site):
        if not get_jwt_claims()['is_Auth']:
            return ({
                'status': 'fail',
                'msg': 'Not authorised to delete stores'
            }, 403)

        try:
            store = StoreModel.find_by_site(site)
            if not store:
                return ({
                    'status': 'fail',
                    'msg': f'Site: {site} not found'
                }, 404)

            store.delete_from_db()
            return {
                'status': 'success',
                'msg': f'Store ({store.store}) deleted'
            }

        except Exception as error:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(error)),
                    "msg": str(error)
                }
            }, 500)


class Stores(Resource):
    def post(self):
        try:
            stores_parser = reqparse.RequestParser()
            stores_parser.add_argument('stores', type=dict, action='append')
            data = stores_parser.parse_args()
            validated_stores = []

            for store in data['stores']:
                validated_store = validate_store(store)
                if not validated_store:
                    return {
                        'status': 'fail',
                        'msg': f'Store: ({store}) not valid'
                    }, 400
                validated_stores.append(validated_store)
            saved_stores = StoreModel.update_many(validated_stores)
            return {
                'status': 'success',
                'msg': {
                    'stores created': saved_stores
                }
            }
        except Exception as error:
            return {'status': 'fail', 'msg': str(error)}, 400
