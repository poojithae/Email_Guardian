import json
import requests
from django.core.serializers.json import DjangoJSONEncoder

class API:
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Connection': 'close'
    }
    
    def __init__(self, base_uri):
        self.base_uri = base_uri

    def _get_path(self, endpoint_key):
        return endpoint_key

    def _get_complete_url(self, path):
        return f'{self.base_uri}/{path}'

    def _request(self, method, path, params=None, payload=None):
        url = self._get_complete_url(path)
        headers = self.headers.copy()
        if 'token' in params:
            headers.update({'Authorization': 'Token ' + params['token']})
        
        response = requests.request(
            method, url, params=params,
            data=json.dumps(payload, cls=DjangoJSONEncoder) if payload else None,
            headers=headers
        )
        response.encoding = 'utf-8'
        return response.json()

    def _GET(self, path, params=None):
        return self._request('GET', path, params=params)

    def _POST(self, path, params=None, payload=None):
        return self._request('POST', path, params=params, payload=payload)

    def _set_attrs_to_values(self, response={}):
        for key in response.keys():
            setattr(self, key, response[key])


class AuthAPI(API):
    BASE_PATH = 'api'
    URLS = {
        'register': 'register/',
        'verify_otp': 'verify-otp/',
        'regenerate_otp': 'regenerate-otp/',
        'login': 'login/',
        'logout': 'logout/',
        'password_reset': 'password-reset/',
        'password_reset_verify': 'password-reset-verify/',
        'password_reset_verified': 'password-reset-verified/',
        'email_change': 'email-change/',
        'email_change_verify': 'email-change-verify/',
        'password_change': 'password-change/',
    }

    def register(self, **kwargs):
        path = self._get_path(self.URLS['register'])
        payload = {
            'email': kwargs.get('email'),
            'password1': kwargs.get('password1'),
            'password2': kwargs.get('password2'),
            'first_name': kwargs.get('first_name'),
            'last_name': kwargs.get('last_name'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def verify_otp(self, **kwargs):
        path = self._get_path(self.URLS['verify_otp'])
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response

    def regenerate_otp(self, **kwargs):
        path = self._get_path(self.URLS['regenerate_otp'])
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response

    def login(self, **kwargs):
        path = self._get_path(self.URLS['login'])
        payload = {
            'email': kwargs.get('email'),
            'password': kwargs.get('password'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def logout(self, **kwargs):
        path = self._get_path(self.URLS['logout'])
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response

    def password_reset(self, **kwargs):
        path = self._get_path(self.URLS['password_reset'])
        payload = {
            'email': kwargs.get('email'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def password_reset_verify(self, **kwargs):
        path = self._get_path(self.URLS['password_reset_verify'])
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response

    def password_reset_verified(self, **kwargs):
        path = self._get_path(self.URLS['password_reset_verified'])
        payload = {
            'code': kwargs.get('code'),
            'password': kwargs.get('password'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def email_change(self, **kwargs):
        path = self._get_path(self.URLS['email_change'])
        payload = {
            'email': kwargs.get('email'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def email_change_verify(self, **kwargs):
        path = self._get_path(self.URLS['email_change_verify'])
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response

    def password_change(self, **kwargs):
        path = self._get_path(self.URLS['password_change'])
        payload = {
            'password': kwargs.get('password'),
        }
        response = self._POST(path, payload=payload)
        self._set_attrs_to_values(response)
        return response

    def users_me(self, **kwargs):
        path = self._get_path('users_me/')
        response = self._GET(path, params=kwargs)
        self._set_attrs_to_values(response)
        return response
