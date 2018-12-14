import json
from collections import OrderedDict
from keycloak.admin import KeycloakAdminBase, KeycloakAdminCollection

__all__ = ('Users',)


class Users(KeycloakAdminBase, KeycloakAdminCollection):
    _defaults_all_query = { # https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_users_2
        'max': -1, # turns off default max (100)
    }
    _paths = {
        'collection': '/auth/admin/realms/{realm}/users',
        'count': '/auth/admin/realms/{realm}/users/count',
    }
    _realm_name = None

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(Users, self).__init__(*args, **kwargs)

    def count(self):
        return self._client.get(
            self._client.get_full_url(
                self.get_path('count', realm=self._realm_name)
            )
        )

    def create(self, username, **kwargs):
        """
        Create a user in Keycloak

        http://www.keycloak.org/docs-api/3.4/rest-api/index.html#_users_resource

        :param str username:
        :param object credentials: (optional)
        :param str first_name: (optional)
        :param str last_name: (optional)
        :param str email: (optional)
        :param boolean enabled: (optional)
        """
        payload = OrderedDict(username=username)

        if 'credentials' in kwargs:
            payload['credentials'] = [kwargs['credentials']]

        if 'first_name' in kwargs:
            payload['firstName'] = kwargs['first_name']

        if 'last_name' in kwargs:
            payload['lastName'] = kwargs['last_name']

        if 'email' in kwargs:
            payload['email'] = kwargs['email']

        if 'enabled' in kwargs:
            payload['enabled'] = kwargs['enabled']

        return self._client.post(
            url=self._url_collection(),
            data=json.dumps(payload)
        )

    def _url_collection_params(self):
        return {'realm': self._realm_name}
