import requests

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from django.utils.translation import ugettext as _
from django.conf import settings
from django.contrib.auth import get_user_model

from .exceptions import UnAuthorized


class JWTAuth(JSONWebTokenAuthentication):
    def get_user(self, user_id):
        try:
            fallback_service = {
                "BASE_URL": "http://localhost:8000"
            }
            response = requests.get(
                f"{settings.MICROSERVICES.get('USER_SERVICE', fallback_service).get('BASE_URL')}/v1/auth/info/{user_id}",
                headers={
                    'Content-Type': 'application/json',
                    'api-key': settings.API_KEY,
                }
            )
            if response.status_code >= 201:
                return None
            user_obj = response.json().get('data')
            User = get_user_model()

            groups = user_obj.pop('groups')
            user_permissions = user_obj.pop('user_permissions')
            user = User(**user_obj)

            user.id = user_id
            user.groups.add(*groups)
            user.user_permissions.add(*user_permissions)

            return user
        except Exception:
            return None

    def get_authorization_header(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', b'')
        if isinstance(auth, str):
            HTTP_HEADER_ENCODING = 'iso-8859-1'
            auth = auth.encode(HTTP_HEADER_ENCODING)
        return auth
    
    def get_jwt_value(self, request):
        auth = self.get_authorization_header(request).split()

        if not auth:
            if (JWT_AUTH_COOKIE := settings.JWT_AUTH.get('JWT_AUTH_COOKIE')):
                return request.COOKIES.get(JWT_AUTH_COOKIE) 
            return None

        if len(auth) > 1:
            msg = _('Invalid Authorization header. Credentials string '
                    'Either Remove header prefix or remove spaces.')
            raise UnAuthorized(msg)

        return auth[0]

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id.
        """
        user_id = payload.get('user_id')

        if not user_id:
            msg = _('Invalid payload.')
            raise UnAuthorized(msg)

        try:
            user = self.get_user(user_id)
            if not user:
                msg = _('Authentication Failed.')
                raise UnAuthorized(msg)
        except Exception:
            msg = _('Authentication Failed.')
            raise UnAuthorized(msg)

        if not user.is_active:
            msg = _('User account is disabled.')
            raise UnAuthorized(msg)

        return user
