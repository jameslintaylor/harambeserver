import os
import binascii
import json
from flask import Flask, session

import pysn.endpoints
from pysn.model import APIError
from pysn.moya import Provider
from model import create_tables, db, Device
from utils import *

app = Flask(__name__)
app.config.update(
    SECRET_KEY='shhh! secret'
)

mitmprovider = Provider(proxies={
                            'http': 'http://localhost:8081',
                            'https': 'http://localhost:8081'
                        },
                        verify_certificates=False)

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(resp):
    db.close()
    return resp

@app.route('/register', methods=['GET'])
@needs_parameters('psn_username', 'psn_password', in_='args')
def register(psn_username, psn_password):
    # get an sso from psn
    try:
        psn_sso = Provider().request(pysn.endpoints.sso(psn_username, psn_password))
    except APIError as e:
        return error(e.message, e.code)

    try:
        # if the user already exists, just update the sso and
        # return the existing auth token
        user = User.get(User.psn_username == psn_username)
        user.psn_sso = psn_sso
        user.save()
    except User.DoesNotExist:
        # generate an auth token and create the user
        auth_token = binascii.hexlify(os.urandom(24)).decode('ascii')
        user = User.create(psn_username=psn_username,
                           psn_sso=psn_sso,
                           auth_token=auth_token)

    return plain(user.auth_token)

@app.route('/login', methods=['GET'])
@needs_parameters('auth_token', in_='args')
def login(auth_token):
    try:
        user = User.get(User.auth_token == auth_token)
        session['auth_token'] = auth_token
        return success("logged in {}".format(user.psn_username))
    except User.DoesNotExist:
        return error("bad token", 401)

@app.route('/logout', methods=['GET'])
@needs_login
def logout(user):
    del session['auth_token']
    return plain("logged out {}".format(user.psn_username))

@app.route('/devices', methods=['GET'])
@needs_login
def devices(user):
    apns_tokens = [device.apns_token for device in user.devices]
    return plain(json.dumps(apns_tokens))

@app.route('/add_push_device', methods=['GET'])
@needs_login
@needs_parameters('apns_token', in_='args')
def add_push_device(user, apns_token):
    # create the device if it doesn't already exist
    _, created = Device.get_or_create(apns_token=apns_token, user=user)
    if created:
        return success("added device {}".format(apns_token))
    else:
        return plain("device already registered")

@app.route('/remove_push_device', methods=['GET'])
@needs_login
@needs_parameters('apns_token', in_='args')
def remove_push_device(user, apns_token):
    try:
        device = Device.get(apns_token=apns_token, user=user)
        device.delete_instance()
        return success("removed device {}".format(device.apns_token))
    except Device.DoesNotExist:
        return error("device isn't registered")

@app.route('/psn_token', methods=['GET'])
@needs_access_token
def psn_token(access_token):
    return plain(access_token)

@app.route('/profile', methods=['GET'])
@needs_access_token
def profile(access_token):
    try:
        profile = Provider().request(pysn.endpoints.profile(access_token))
    except APIError as e:
        return error(e.message), e.code

    content = json.dumps(profile.__dict__)
    return plain(content)

@app.route('/friends', methods=['GET'])
@needs_access_token
def friends(access_token):
    try:
        friends = Provider().request(pysn.endpoints.friends(access_token))
    except APIError as e:
        return error(e.message), e.code

    content = json.dumps([profile.__dict__ for profile in friends])
    return plain(content)

if __name__ == '__main__':
    create_tables()
    app.run(debug=True)
