from keycloak.admin import KeycloakAdminCollection, KeycloakAdminBaseElement

__all__ = ('Realm', 'Realms',)


class Realm(KeycloakAdminBaseElement):
    _name = None
    _paths = {
        'single': '/auth/admin/realms/{realm_name}',
    }

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(Realm, self).__init__(*args, **kwargs)

    @property
    def clients(self):
        from keycloak.admin.clients import Clients
        return Clients(realm_name=self._realm_name, admin=self._admin)

    @property
    def users(self):
        from keycloak.admin.users import Users
        return Users(realm_name=self._realm_name, admin=self._admin)

    @property
    def roles(self):
        from keycloak.admin.roles import RealmRoles
        return RealmRoles(realm_name=self._realm_name, admin=self._admin)

    @property
    def groups(self):
        from keycloak.admin.groups import Groups
        return Groups(realm_name=self._realm_name, admin=self._admin)


class Realms(KeycloakAdminCollection):
    _paths = {
        'collection': '/auth/admin/realms'
    }
    _itemclass = Realm

    def __init__(self, *args, **kwargs):
        super(Realms, self).__init__(*args, **kwargs)

    def by_name(self, name):
        return Realm(realm_name=name, admin=self._admin)

    def _url_item_params(self, data):
        return dict(realm_name=data['realm'], admin=self._admin)
