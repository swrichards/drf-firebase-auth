import base64
import logging
import os
import tempfile

from django.core.exceptions import ImproperlyConfigured
from firebase_admin import auth, credentials, initialize_app
from rest_framework import authentication

from .settings import app_settings

logger = logging.getLogger(__name__)


# TODO: According to the Firebase Admin docs, the initialize_app() function
# should be able to read JSON directly from the FIREBASE_CONFIG enviornment
# variable. I haven't however been able to get this to work.

if app_settings['CREDENTIALS']:
    # Path to credentials set?
    creds_obj = credentials.Certificate(app_settings['CREDENTIALS'])
    logger.debug('Loading Firebase credentials from {path}'
                 .format(path=app_settings['CREDENTIALS']))
elif os.getenv('FIREBASE_CREDS', None):
    # Check for credentials in environment in base64
    creds_json = base64.b64decode(os.getenv('FIREBASE_CREDS'))
    with tempfile.NamedTemporaryFile() as fp:
        fp.write(creds_json)
        fp.seek(0)
        creds_obj = credentials.Certificate(os.path.abspath(fp.name))

    logger.debug("Loading Firebase credentials from FIREBASE_CREDS env var")
else:
    # Final option is for Firebase to try and detect credentials in a GCP
    # environment, e.g. through GOOGLE_APPLICATION_CREDENTIALS
    # Explicitly set credentials to None to force this
    creds_obj = None


try:
    initialize_app(credential=creds_obj)
except Exception:
    logger.debug("Unable to configure firebase app", exc_info=True)
    raise ImproperlyConfigured("Unable to locate Firebase credentials")


class FirebaseAuthentication(authentication.BaseAuthentication):
    """
    Authentication class for Django Rest Framework to authenticate requests
    using JWT Bearer Tokens supplied by a Firebase application.
    """
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', None)
        if not auth_header:
            logger.debug("No Authorization header found")
            return None

        # Validate Authorization header schema
        schema = app_settings['AUTH_HEADER_SCHEMA']
        if not auth_header.startswith('{schema} '.format(schema=schema)):
            logger.debug("Authorization header does not start with 'Bearer'")
            return None

        # Get base64 encoded token from header
        _, id_token = auth_header.split('{schema} '.format(schema=schema))
        logger.debug("Got ID Token: {}".format(id_token))

        try:
            # Should we check for revoked tokens?
            check_revoked = app_settings['ALLOW_REVOKED'] is False

            # Attempt to decode and verify token
            decoded_token = auth.verify_id_token(id_token,
                                                 check_revoked=check_revoked)
            logger.debug("Successfully decoded token: {decoded_token}"
                         .format(decoded_token=decoded_token))

            # Disallow unverified Emails if flag if set
            if (not app_settings['ALLOW_UNVERIFIED_EMAIL'] and
                    not decoded_token['email_verified']):
                logger.warning('Tokens with unverified emails not allowed')
                return None
        except ValueError:
            logger.warning("Invalid JWT or bad Firebase project ID",
                           exc_info=True)
            return None
        except auth.AuthError:
            logger.warning("JWT token expired", exc_info=True)
            return None
        except Exception:
            logger.warning("Unknown exception while verifying token",
                           exc_info=True)
            return None

        try:
            User = app_settings['USER_MODEL']
            jwt_lookup_key = decoded_token.get(app_settings['JWT_LOOKUP_KEY'])
            logger.debug("Looking up Django user [%s=%s] on model %s" %
                         (app_settings['USER_LOOKUP_KEY'], jwt_lookup_key,
                          type(User)))
            user_lookup = {
                app_settings['USER_LOOKUP_KEY']: jwt_lookup_key
            }
            user = User.objects.get(**user_lookup)
        except User.DoesNotExist:
            logger.warning('The user does not exist', exc_info=True)
            return None

        return (user, None,)
