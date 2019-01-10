import json
from collections import OrderedDict
from keycloak.admin import KeycloakAdminBase, KeycloakAdminCollection

__all__ = ('Users',)

ROLE_KWARGS = [
    'description',
    'name',
    'id',
    'client_role',
    'composite',
    'composites',
    'container_id',
    'scope_param_required'
]

def to_camel_case(snake_cased_str):
    components = snake_cased_str.split('_')
    # We capitalize the first letter of each component except the first one
    # with the 'title' method and join them together.
    return components[0] + ''.join(map(str.capitalize, components[1:]))

class Users(KeycloakAdminBase, KeycloakAdminCollection):
    _defaults_all_query = { # https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_users_2
        'max': -1, # turns off default max (100)
    }
    _paths = {
        'collection': '/auth/admin/realms/{realm}/users',
        'count': '/auth/admin/realms/{realm}/users/count',
        'mapping': '/auth/admin/realms/{realm}/users/{userid}/role-mappings',
        'mapping_client': '/auth/admin/realms/{realm}/users/{userid}/role-mappings/clients/{client}',
        'impersonate': '/auth/admin/realms/{realm}/users/{userid}/impersonation',
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

    def by_id(self, id):
        return User(client=self._client, realm_name=self._realm_name, id=id)

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

class User(KeycloakAdminBase):
    _id = None
    _realm_name = None

    _paths = {
        'collection': '/auth/admin/realms/{realm}/users',
        'count': '/auth/admin/realms/{realm}/users/count',
        'mapping': '/auth/admin/realms/{realm}/users/{userid}/role-mappings',
        'mapping_client': '/auth/admin/realms/{realm}/users/{userid}/role-mappings/clients/{client}',
        'mapping_client_av': '/auth/admin/realms/{realm}/users/{userid}/role-mappings/clients/{client}/available',
        'impersonate': '/auth/admin/realms/{realm}/users/{userid}/impersonation',
    }

    def __init__(self, realm_name, id, *args, **kwargs):
        self._realm_name = realm_name
        self._id = id
        super(User, self).__init__(*args, **kwargs)

    def role_mapping(self):
        """
        get role mappings (realm and client) for an user
        https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_role_mappings_2

        """
        return self._client.get(
            self._client.get_full_url(
                self.get_path('mapping', realm=self._realm_name, userid=self._id)
            )
        )

    def client_role_mapping(self, client_id):
        """
        get client role mappings for an user
        https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_client_level_role_mappings_for_the_user_and_the_app
        """
        return self._client.get(
            self._client.get_full_url(
                self.get_path('mapping_client', realm=self._realm_name, userid=self._id, client=client_id)
            )
        )


    def client_role_available(self, client_id):
        """
        get available roles by client for an user (assigned roles not shown)
        https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_available_client_level_roles_that_can_be_mapped_to_the_user
        """
        return self._client.get(
            self._client.get_full_url(
                self.get_path('mapping_client_av', realm=self._realm_name, userid=self._id, client=client_id)
            )
        )

    def impersonate(self):
        payload = {}
        payload['id'] = self._id
        payload['realm'] = self._realm_name
        return self._client.post(
            self._client.get_full_url(
                self.get_path('impersonate', realm=self._realm_name, userid=self._id)
            ), data=json.dumps(payload)
        )

    def delete_client_role_from_user(self,client_id,role_name, **kwargs):
        """
        Delete client-level roles from user role mapping
        https://www.keycloak.org/docs-api/2.5/rest-api/index.html#__delete_client_level_roles_from_user_role_mapping_2
        :param client_id: id of the client
        :param role_name: Role name
        :return:
        """
        payload = OrderedDict(name=role_name)
        arrayRP =[]
        for key in ROLE_KWARGS:
            if key in kwargs:
                payload[to_camel_case(key)] = kwargs[key]
        arrayRP.append(payload)
        return self._client.delete(
            self._client.get_full_url(
                self.get_path('mapping_client', realm=self._realm_name, userid=self._id, client=client_id)
            ), params=json.dumps(arrayRP)
        )

    def add_client_role_to_user(self,client_id,role_name, **kwargs):
        """
        Add client-level roles to the user role mapping
        https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_add_client_level_roles_to_the_user_role_mapping_2
        :param client_id: id of the client
        :param role_name: Role name
        :return:
        """
        payload = OrderedDict(name=role_name)
        arrayRP =[]
        for key in ROLE_KWARGS:
            if key in kwargs:
                payload[to_camel_case(key)] = kwargs[key]
        arrayRP.append(payload)
        return self._client.post(
            self._client.get_full_url(
                self.get_path('mapping_client', realm=self._realm_name, userid=self._id, client=client_id)
            ), data=json.dumps(arrayRP)
        )
