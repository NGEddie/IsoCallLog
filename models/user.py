from pymodm import MongoModel, fields, connect, errors
from bson.objectid import ObjectId
import bcrypt

from db import db

connect(db)


class UserModel(MongoModel):
    name = fields.CharField(required=True)
    email = fields.EmailField(required=True)
    password = fields.CharField(required=True)

    def __str__(self):
        return (
            "User:"
            + f"\n ID: {self.pk}"
            + f"\n Name: {self.name}"
            + f"\n EMail: {self.email}"
        )

    def json(self):
        return {
            "_id": str(self._id),
            "name": self.name,
            "email": self.email,
        }

    @classmethod
    def find_by_id(cls, _id):
        try:
            return cls.objects.get({"_id": ObjectId(_id)})
        except cls.DoesNotExist:
            return None

    @classmethod
    def find_by_email(cls, email):
        try:
            return cls.objects.raw({"email": email}).first()
        except cls.DoesNotExist:
            return None
