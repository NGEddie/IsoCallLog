from settings import db_user, db_password, cluster, database

db = f"mongodb+srv://{db_user}:{db_password}@{cluster}/{database}?retryWrites=true&w=majority&ssl=true"

#  mongo_database = MongoClient(cluster_string)

#  db = mongo_database[f"{database}"]
