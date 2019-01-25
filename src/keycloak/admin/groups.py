from keycloak.admin import KeycloakAdminCollection, KeycloakAdminBaseElement
from keycloak.admin.users import User
from collections import OrderedDict

__all__ = ('Group', 'Groups',)


class Group(KeycloakAdminBaseElement):
    _id = None
    _realm_name = None
    _paths = {
        'single': '/auth/admin/realms/{realm_name}/groups/{id}',
    }
    _idents = {'path': 'path'}

    def __init__(self, realm_name, id, *args, **kwargs):
        self._id = id
        self._realm_name = realm_name
        super(Group, self).__init__(*args, **kwargs)

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self().get('name')

    @property
    def path(self):
        return self().get('path')

    @property
    def subGroups(self):
        return [
            Group(params=sg, admin=self._admin, realm_name=self._realm_name, id=sg['id'])
            for sg in self().get('subGroups')
        ]

    @property
    def members(self):
        return GroupMembers(admin=self._admin, realm_name=self._realm_name, group_id=self._id)



class Groups(KeycloakAdminCollection):
    _defaults_all_query = { # https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_users_2
        'max': -1, # turns off default max (100)
    }
    _paths = {
        'collection': '/auth/admin/realms/{realm_name}/groups',
        'count': '/auth/admin/realms/{realm_name}/groups/count',
    }
    _realm_name = None
    _itemclass = Group

    def __init__(self, realm_name, *args, **kwargs):
        self._realm_name = realm_name
        super(Groups, self).__init__(*args, **kwargs)

    def by_id(self, group_id):
        return Groups(admin=self._admin, realm_name=self._realm_name, group_id=group_id)

    # def by_name(self, name):
    #     res = self.unsorted().all(username=name)
    #     if res:
    #         return self.by_id(res[0]['id'])

    def __len__(self):
        return self.count()

    def count(self):
        return self._admin.get(
            self._admin.get_full_url(self.get_path_dyn('count'))
        )

    # def create(self, username, **kwargs):
    #     """
    #     Create a user in Keycloak

    #     http://www.keycloak.org/docs-api/3.4/rest-api/index.html#_users_resource

    #     :param str username:
    #     :param object credentials: (optional)
    #     :param str first_name: (optional)
    #     :param str last_name: (optional)
    #     :param str email: (optional)
    #     :param boolean enabled: (optional)
    #     """
    #     payload = OrderedDict(username=username)

    #     if 'credentials' in kwargs:
    #         payload['credentials'] = [kwargs['credentials']]

    #     if 'first_name' in kwargs:
    #         payload['firstName'] = kwargs['first_name']

    #     if 'last_name' in kwargs:
    #         payload['lastName'] = kwargs['last_name']

    #     if 'email' in kwargs:
    #         payload['email'] = kwargs['email']

    #     if 'enabled' in kwargs:
    #         payload['enabled'] = kwargs['enabled']

    #     return self._admin.post(
    #         url=self._url_collection(),
    #         data=json.dumps(payload)
    #     )

    def _url_item_params(self, data):
        return dict(
            id=data['id'], admin=self._admin, realm_name=self._realm_name,
        )


class GroupMembers(KeycloakAdminCollection):
    _defaults_all_query = { # https://www.keycloak.org/docs-api/2.5/rest-api/index.html#_get_users_2
        'max': -1, # turns off default max (100)
    }
    _paths = {
        'collection': '/auth/admin/realms/{realm_name}/groups/{group_id}/members',
        # 'count': '/auth/admin/realms/{realm_name}/users/count',
    }
    _realm_name = None
    _itemclass = User

    def __init__(self, realm_name, group_id, *args, **kwargs):
        self._realm_name = realm_name
        self._group_id = group_id
        super(GroupMembers, self).__init__(*args, **kwargs)

    def _url_item_params(self, data):
        return dict(
            id=data['id'], admin=self._admin, realm_name=self._realm_name,
        )
