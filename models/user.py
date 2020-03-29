from pymodm import MongoModel, fields, connect
from bson.objectid import ObjectId

from settings import DB, ROLES, DEFAULT_ROLE

connect(DB)


class UserModel(MongoModel):
    username = fields.CharField(required=True)
    firstName = fields.CharField(required=True)
    lastName = fields.CharField(required=True)
    email = fields.EmailField(required=True)
    password = fields.CharField(required=True)
    role = fields.CharField(mongo_name="access_level",
                            choices=ROLES,
                            default=DEFAULT_ROLE)

    def json(self):
        return {
            "_id": str(self._id),
            "username": self.username,
            "name": str(self.firstName + " " + self.lastName),
            "email": self.email,
            "role": self.role
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

    @classmethod
    def find_by_username(cls, username):
        try:
            return cls.objects.raw({"username": username}).first()
        except cls.DoesNotExist:
            return None

    @classmethod
    def update_many(cls, users):
        #  print([cls(**user) for user in users])
        saved_users = cls.objects.bulk_create([cls(**user) for user in users],
                                              retrieve=True)
        return [user.username for user in saved_users]

    def update_user(self):
        self.save()

    def delete_from_db(self):
        self.delete()

    def full_name(self):
        return f'{self.firstName} {self.lastName}'
