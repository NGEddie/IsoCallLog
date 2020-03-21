from pymodm import MongoModel, fields, connect
from bson.objectid import ObjectId

from settings import db

connect(db)


class StoreModel(MongoModel):
    site = fields.IntegerField(required=True, primary_key=True)
    store = fields.CharField(required=True)

    def __str__(self):
        return f"Site: \t{self.site}\nStore: \t{self.store}"

    def json(self):
        return {"site": self.site, "store": self.store}

    @classmethod
    def find_by_site(cls, site):
        try:
            return cls.objects.get({"_id": int(site)})
        except cls.DoesNotExist:
            return None
