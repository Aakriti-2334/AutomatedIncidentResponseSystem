from flask_login import UserMixin
from werkzeug.security import check_password_hash
from services import database_service

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get(user_id):
        user_data = database_service.get_user_by_id(user_id)
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        user_data = database_service.get_user_by_username(username)
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['password_hash'])
        return None
