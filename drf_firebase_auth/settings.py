from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.module_loading import import_string

USER_SETTINGS = getattr(settings, 'DRF_FIREBASE_AUTH', None)

DEFAULTS = {
    'JWT_LOOKUP_KEY': 'email',
    'USER_LOOKUP_KEY': 'email',
    'USER_MODEL': None,
    'AUTH_HEADER_SCHEMA': 'Bearer',
    'ALLOW_UNVERIFIED_EMAIL': True,
    'ALLOW_REVOKED': False,
    'CREDENTIALS': None
}

DEFAULTS['USER_MODEL'] = get_user_model()

if USER_SETTINGS:
    DEFAULTS.update(USER_SETTINGS)

    if USER_SETTINGS['USER_MODEL']:
        user_model = import_string(USER_SETTINGS['USER_MODEL'])

app_settings = DEFAULTS
