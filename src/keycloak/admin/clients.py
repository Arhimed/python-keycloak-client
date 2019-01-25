from keycloak.admin import KeycloakAdminCollection, KeycloakAdminBaseElement

__all__ = ('Client', 'Clients',)


class Client(KeycloakAdminBaseElement):
    _id = None
    _realm_name = None
    _paths = {
        'single': '/auth/admin/realms/{realm_name}/clients/{id}',
    }
    _idents = {'name': 'clientId'}

    def __init__(self, realm_name, id, *args, **kwargs):
        self._id = id
        self._realm_name = realm_name
        super(Client, self).__init__(*args, **kwargs)

    @property
    def id(self):
        return self._id

    @property
    def roles(self):
        from keycloak.admin.roles import ClientRoles
        return ClientRoles(admin=self._admin, realm_name=self._realm_name, client=self)


class Clients(KeycloakAdminCollection):
    _realm_name = None
    _paths = {
        'collection': '/auth/admin/realms/{realm_name}/clients'
    }
    _itemclass = Client

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(Clients, self).__init__(*args, **kwargs)

    def by_id(self, id):
        return Client(admin=self._admin, realm_name=self._realm_name, id=id)

    def by_name(self, name):
        res = self.unsorted().all(clientId=name)
        if res:
            return self.by_id(res[0]['id'])

    def _url_item_params(self, data):
        return dict(
            id=data['id'], admin=self._admin, realm_name=self._realm_name
        )

