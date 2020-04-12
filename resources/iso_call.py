from flask_restful import Resource, reqparse
from bson import ObjectId
from pymongo import errors as pymongo_errors
from pymodm import errors as pymodm_errors

from models.iso_call import CallModel
from models.user import UserModel
from models.store import StoreModel

_call_parser = reqparse.RequestParser()

_call_parser.add_argument("call_date")
_call_parser.add_argument("store")
_call_parser.add_argument("vet_nurse")
_call_parser.add_argument("pet")
_call_parser.add_argument("source")
_call_parser.add_argument("quantity")
_call_parser.add_argument("problem")
_call_parser.add_argument("auth_code")
_call_parser.add_argument("notes", action="append")


class NewCall(Resource):
    @classmethod
    def post(cls):
        try:
            data = _call_parser.parse_args()
            vet_nurse = UserModel.find_by_username(data['vet_nurse'])
            store = StoreModel.find_by_site(data['store'])

            if not store:
                return {
                    'status': 'fail',
                    'msg': f'Store Number: {data["store"]} not found'
                }, 404

            if not vet_nurse:
                return {
                    'status': 'fail',
                    'msg': f'Vet Nurse: {data["vet_nurse"]} not found'
                }

            data['fpp'] = store.fpp._id
            data['store'] = store.site
            data['vet_nurse'] = vet_nurse._id
            new_call = CallModel(**data).save_to_db()

            return {'status': 'success', 'msg': {'Iso Call': new_call.json()}}
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


class Call(Resource):
    @classmethod
    def get(cls, id):
        try:
            acall = CallModel.find_by_id(id)
            return ({'status': 'success', 'msg': {'call': acall.json()}}, 200)
        except Exception as error:
            print(error)

    @classmethod
    def put(cls, id):
        try:
            call = CallModel.find_by_id(id)
            if not call:
                return {
                    'status': 'fail',
                    'msg': f'Call id ({id}) not found'
                }, 404

            data = _call_parser.parse_args()

            if data['vet_nurse']:
                vet_nurse = UserModel.find_by_username(data['vet_nurse'])
                if not vet_nurse:
                    return {
                        'status': 'fail',
                        'msg': f'Vet Nurse ({data["vet_nurse"]}) not found'
                    }, 404

            for field, value in data.items():
                if value:
                    setattr(call, field, value)

            call.update_call()
            return {'status': 'success', 'msg': f'Call Updated: {call.json()}'}

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
    def delete(cls, id):

        try:
            call = CallModel.find_by_id(id)
            if not call:
                return {
                    'status': 'fail',
                    'msg': f'Call (id: {id}) not found'
                }, 404

            call.delete_from_db()
            return {'status': 'success', 'msg': 'call deleted'}
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


class AuthCode(Resource):
    @classmethod
    def get(cls, auth_code):
        try:
            call = CallModel.find_by_auth_code(auth_code)
            if not call:
                return {
                    'status': 'fail',
                    'msg': f'AuthCode ({auth_code} not found)'
                }, 404
            return {'status': 'success', 'msg': call.json()}
        except pymongo_errors.OperationFailure as error:
            return {
                'status': 'fail',
                'msg': {
                    'type': str(type(error)),
                    'msg': str(error)
                }
            }, 500
        except Exception as error:
            return ({
                "status": "fail",
                "error": {
                    "type": str(type(error)),
                    "msg": str(error)
                }
            }, 500)
