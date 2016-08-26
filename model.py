from enum import Enum
from datetime import datetime, timedelta
from dateutil import parser as dateparser
from peewee import SqliteDatabase, Model, CharField, ForeignKeyField, DateTimeField, Field

from pysn.model import APIToken

db = SqliteDatabase('harambe.db')

class BaseModel(Model):
    class Meta:
        database = db

class APITokenField(Field):
    db_field = 'psn_token'

    def db_value(self, token):
        if not token:
            return
        return '{}|{}'.format(token.value, str(token.expiry_date))

    def python_value(self, db_value):
        if not db_value:
            return
        s_value, s_expiry_date = tuple(db_value.split('|'))
        return APIToken(s_value, dateparser.parse(s_expiry_date))

class User(BaseModel):
    auth_token = CharField(unique=True)
    psn_username = CharField(unique=True)
    psn_sso = CharField(unique=True)
    psn_access_token = APITokenField(unique=True, null=True)
    psn_refresh_token = APITokenField(unique=True, null=True)

class Device(BaseModel):
    apns_token = CharField(unique=True)
    # one-to-many relationship between a user and his/her devices
    user = ForeignKeyField(User, related_name='devices')

def create_tables():
    db.connect()
    db.create_tables([User, Device], safe=True)
