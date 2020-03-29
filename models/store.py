from pymodm import MongoModel, fields, connect

from settings import DB
from models.user import UserModel

connect(DB)


class StoreModel(MongoModel):
    site = fields.IntegerField(required=True, primary_key=True)
    store = fields.CharField(required=True)
    fpp = fields.ReferenceField(UserModel)
    region = fields.CharField(required=True)
    area = fields.CharField(required=True)

    def __str__(self):
        return str(self.json())

    def json(self):
        return {
            "site": self.site,
            "store": self.store,
            "region": self.region,
            "area": self.area,
            "fpp": self.fpp.username,
        }

    @classmethod
    def find_by_site(cls, site):
        try:
            return cls.objects.get({"_id": int(site)})
        except cls.DoesNotExist:
            return None

    def update_store(self):
        self.save()

    def delete_from_db(self):
        self.delete()
