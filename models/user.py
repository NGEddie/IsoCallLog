from pymodm import MongoModel, fields, connect
from bson.objectid import ObjectId

from settings import db, roles, default_role

connect(db)


class UserModel(MongoModel):
    username = fields.CharField(required=True)
    email = fields.EmailField(required=True)
    password = fields.CharField(required=True)
    role = fields.CharField(mongo_name="access_level", choices=roles, default=default_role)

    def __str__(self):
        return f"User:\n\tID: {self.pk}\n\tUsername: {self.username}\n\tEMail: {self.email}\n\tRole: {self.role}"

    def json(self):
        return {"_id": str(self._id), "username": self.username, "email": self.email, "role": self.role}

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

    @classmethod
    def find_by_username(cls, username):
        try:
            return cls.objects.raw({"username": username}).first()
        except cls.DoesNotExist:
            return None

    def update_user(self):
        self.save()

    def delete_from_db(self):
        self.delete()
