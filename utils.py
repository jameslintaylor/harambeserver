from functools import wraps
from flask import render_template, request, session

import pysn.endpoints
from pysn.moya import Provider
from pysn.model import UserProfile
from model import User

def error(message, code=400):
    return render_template('error.html', message=message), code

def success(message):
    return render_template('success.html', message=message)

def plain(content):
    return render_template('plain.html', content=content)

def needs_parameters(*params, in_):
    """extracts the parameters from either request.args or request.form
    (in_ can either be 'args' or 'form'). if the parameters are not there,
    returns a 400 status code displaying the first missing parameter"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            d = getattr(request, in_)
            try:
                kwargs.update({param: d[param] for param in params})
            except KeyError as e:
                return error("missing parameter '{}'".format(e.args[0]), 400)
            return f(*args, **kwargs)
        return decorated
    return decorator

def accepts_parameters(*params, in_):
    """extracts the parameters from either request.args or request.form
    (in_ can either be 'args' or 'form'). missing parameters are replaced
    with None"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            d = getattr(request, in_)
            kwargs.update({param: d.get(param, None) for param in params})
            return f(*args, **kwargs)
        return decorated
    return decorator

def needs_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            auth_token = session['auth_token']
        except KeyError:
            return error("need to login first", 401)

        try:
            user = User.get(auth_token=auth_token)
        except User.DoesNotExist:
            return error("whoops! user not in database :(", 500)

        kwargs['user'] = user
        return f(*args, **kwargs)

    return decorated

def needs_access_token(f):
    @wraps(f)
    @needs_login
    def decorated(*args, **kwargs):
        user = kwargs['user']
        del kwargs['user']
        # have a valid access token, use it
        if user.psn_access_token and user.psn_access_token.is_valid:
            print("reusing access token for {}".format(user.psn_username))
        # have a valid refresh token, get new tokens
        elif user.psn_refresh_token and user.psn_refresh_token.is_valid:
            print("refreshing tokens with refresh token for {}".format(user.psn_username))
            endpoint = pysn.endpoints.token({'refresh_token': user.psn_refresh_token.value})
            user.psn_access_token, user.psn_refresh_token = Provider().request(endpoint)
            user.save()
        # use the sso to get new tokens
        else:
            print("getting new tokens for {}".format(user.psn_username))
            # todo: - make this nicer
            provider = Provider()
            provider.session.cookies['npsso'] = user.psn_sso
            auth_code_endpoint = pysn.endpoints.auth_code()
            auth_code = provider.request(auth_code_endpoint)
            token_endpoint = pysn.endpoints.token({'auth_code': auth_code})
            user.psn_access_token, user.psn_refresh_token = provider.request(token_endpoint)
            user.save()
        kwargs['access_token'] = user.psn_access_token.value
        return f(*args, **kwargs)
    return decorated
