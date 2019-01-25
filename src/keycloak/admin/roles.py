import json
from collections import OrderedDict
from keycloak.admin import KeycloakAdminCollection, KeycloakAdminBaseElement
from keycloak.helpers import to_camel_case

ROLE_KWARGS = [
    'description',
    'id',
    'client_role',
    'composite',
    'composites',
    'container_id',
    'scope_param_required'
]

__all__ = ('Role', 'Roles', 'RealmRole', 'RealmRoles', 'ClientRole', 'ClientRoles',)


class Roles(KeycloakAdminCollection):
    def create(self, name, **kwargs):
        """
        Create new role

        http://www.keycloak.org/docs-api/3.4/rest-api/index.html
        #_roles_resource

        :param str name: Name for the role
        :param str description: (optional)
        :param str id: (optional)
        :param bool client_role: (optional)
        :param bool composite: (optional)
        :param object composites: (optional)
        :param str container_id: (optional)
        :param bool scope_param_required: (optional)
        """
        payload = OrderedDict(name=name)

        for key in ROLE_KWARGS:
            if key in kwargs:
                payload[to_camel_case(key)] = kwargs[key]

        return self._admin.post(
            url=self._url_collection(),
            data=json.dumps(payload)
        )

    def by_name(self, role_name):
        return Role(role_name=role_name, admin=self._admin)


class Role(KeycloakAdminBaseElement):
    _role_name = None

    def __init__(self, role_name, *args, **kwargs):
        self._role_name = role_name
        super(Role, self).__init__(*args, **kwargs)

    def update(self, name, **kwargs):
        """
        Update existing role.

        http://www.keycloak.org/docs-api/3.4/rest-api/index.html#_roles_resource

        :param str name: Name for the role
        :param str description: (optional)
        :param str id: (optional)
        :param bool client_role: (optional)
        :param bool composite: (optional)
        :param object composites: (optional)
        :param str container_id: (optional)
        :param bool scope_param_required: (optional)
        """
        payload = OrderedDict(name=name)

        for key in ROLE_KWARGS:
            if key in kwargs:
                payload[to_camel_case(key)] = kwargs[key]

        return self._admin.put(
            url=self._admin.get_full_url(self.get_path_dyn('single')),
            data=json.dumps(payload)
        )



class RealmRole(Role):
    _realm_name = None
    _paths = {
        'single': '/auth/admin/realms/{realm_name}/roles/{role_name}'
    }

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(RealmRole, self).__init__(*args, **kwargs)

    # def __repr__(self):
    #     return '<%s object realm="%s" role="%s">' % (
    #         self.__class__.__name__, self._realm_name, self._role_name)


class RealmRoles(Roles):
    _realm_name = None
    _paths = {
        'collection': '/auth/admin/realms/{realm_name}/roles'
    }
    _itemclass = RealmRole

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(RealmRoles, self).__init__(*args, **kwargs)

    def by_name(self, role_name):
        return RealmRole(role_name=role_name, admin=self._admin, realm_name=self._realm_name)

    def _url_item_params(self, data):
        return dict(
            admin=self._admin, realm_name=self._realm_name, role_name=data['name']
        )

class ClientRole(RealmRole):
    _client = None
    _paths = {
        'single': '/auth/admin/realms/{realm_name}/clients/{client_id}/roles/{role_name}'
    }

    def __init__(self, client, *args, **kwargs):
        super(ClientRole, self).__init__(*args, **kwargs)

        from keycloak.admin.clients import Client
        if isinstance(client, Client):
            self._client = client
        else:
            self._client = Client(admin=self._admin, realm_name=self._realm_name, id=client)

    @property
    def _client_id(self):
        return self._client.id


class ClientRoles(RealmRoles):
    _client = None
    _paths = {
        'collection': '/auth/admin/realms/{realm_name}/clients/{client_id}/roles'
    }
    _itemclass = ClientRole

    def __init__(self, client, *args, **kwargs):
        super(ClientRoles, self).__init__(*args, **kwargs)

        from keycloak.admin.clients import Client
        if isinstance(client, Client):
            self._client = client
        else:
            self._client = Client(admin=self._admin, realm_name=self._realm_name, id=client)

    @property
    def _client_id(self):
        return self._client.id

    def by_name(self, role_name):
        return ClientRole(role_name=role_name, admin=self._admin, realm_name=self._realm_name, client=self._client)

    def _url_item_params(self, data):
        return dict(
           admin=self._admin, realm_name=self._realm_name, client=self._client, role_name=data['name']
        )



