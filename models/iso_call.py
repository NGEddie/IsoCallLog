from pymodm import MongoModel, fields, connect
from bson import ObjectId

from models.store import StoreModel
from models.user import UserModel

from settings import DB, PETS, SOURCE

connect(DB)


class CallModel(MongoModel):
    call_date = fields.DateTimeField(required=True)
    store = fields.ReferenceField(StoreModel, required=True, blank=False)
    vet_nurse = fields.ReferenceField(UserModel, required=True, blank=False)
    pet = fields.CharField(required=True, choices=PETS, blank=False)
    fpp = fields.ReferenceField(UserModel, required=True, blank=False)
    source = fields.CharField(required=True, choices=SOURCE, blank=False)
    quantity = fields.IntegerField(required=True,
                                   min_value=1,
                                   max_value=30,
                                   blank=False)
    problem = fields.CharField(required=True)
    auth_code = fields.CharField(required=True, blank=False)
    notes = fields.ListField()

    def json(self):
        return {
            "id": str(self._id),
            "site": self.store.store,
            "vet nurse": self.vet_nurse.full_name(),
            "fpp": self.fpp.full_name(),
            "pet": self.pet,
            "source": self.source,
            "quantity": self.quantity,
            "problem": self.problem,
            "auth_code": self.auth_code,
            "notes": self.notes
        }

    @classmethod
    def find_by_id(cls, id):
        try:
            return cls.objects.get({"_id": ObjectId(id)})
        except cls.DoesNotExist:
            return None

    @classmethod
    def find_by_auth_code(cls, auth_code):
        try:
            return cls.objects.get({"auth_code": auth_code})
        except cls.DoesNotExist:
            return None

    def save_to_db(self):
        return self.save()

    def update_call(self):
        return self.save()

    def delete_from_db(self):
        return self.delete()
