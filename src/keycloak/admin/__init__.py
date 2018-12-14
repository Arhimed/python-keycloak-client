import abc
from urllib import urlencode

__all__ = (
    'KeycloakAdmin',
    'KeycloakAdminBase',
    'KeycloakAdminCollection',
)


class KeycloakAdminBase(object):
    _client = None
    _paths = None

    def __init__(self, client):
        """
        :param keycloak.admin.KeycloakAdmin client:
        """
        self._client = client

    def get_path(self, name, **kwargs):
        if self._paths is None:
            raise NotImplementedError()

        return self._paths[name].format(**kwargs)


class KeycloakAdmin(object):
    _realm = None
    _paths = {
        'root': '/'
    }
    _token = None

    def __init__(self, realm):
        """
        :param keycloak.realm.KeycloakRealm realm:
        """
        self._realm = realm

    def root(self):
        return self.get(
            self.get_full_url(self._paths['root'])
        )

    def get_full_url(self, *args, **kwargs):
        return self._realm.client.get_full_url(*args, **kwargs)

    def set_token(self, token):
        """
        Set token to authenticate the call or a callable which will be called
        to get the token.

        :param str | callable token:
        :rtype: KeycloakAdmin
        """
        self._token = token
        return self

    @property
    def realms(self):
        from keycloak.admin.realm import Realms
        return Realms(client=self)

    def post(self, url, data, headers=None, **kwargs):
        return self._realm.client.post(
            url=url, data=data, headers=self._add_auth_header(headers=headers)
        )

    def put(self, url, data, headers=None, **kwargs):
        return self._realm.client.put(
            url=url, data=data, headers=self._add_auth_header(headers=headers)
        )

    def get(self, url, headers=None, **kwargs):
        return self._realm.client.get(
            url=url, headers=self._add_auth_header(headers=headers)
        )

    #
    # def delete(self, url, headers, **kwargs):
    #     return self.session.delete(url, headers=headers, **kwargs)

    def _add_auth_header(self, headers=None):
        if callable(self._token):
            token = self._token()
        else:
            token = self._token

        headers = headers or {}
        headers['Authorization'] = "Bearer {}".format(token)
        headers['Content-Type'] = 'application/json'
        return headers


class KeycloakAdminCollection(object):
    __metaclass__ = abc.ABCMeta
    _defaults_all_query = {} # default query-parameters
    _sort_col = None
    _sort_asc = True

    def all(self, **kwargs):
        query = self._defaults_all_query.copy()
        query.update(kwargs)
        return self._all_sorted(self._client.get(self._url_collection(**query)))

    def all_on(self, col, sort=True, **kwargs):
        res = self.unsorted().all(**kwargs)
        if col is not None:
            res = [u[col] for u in res]
            if sort:
                res.sort(key=lambda v: v.lower()) # case insensitive sorting
        return res

    def sorted_by(self, col, asc=True):  # scope
        self._sort_col = col
        self._sort_asc = asc
        return self

    def unsorted(self):  # scope
        self._sort_col = None
        return self

    def _all_sorted(self, res): # should be called in all-method by inherited class on request-result
        if self._sort_col:
            res.sort(key=lambda v: v[self._sort_col].lower(), reverse=not self._sort_asc) # case insensitive sorting
        return res

    def _all_reset(self):
        self._sort_col = None
        self._sort_asc = True

    def _url_collection(self, **kwargs): # TODO generalize?
        params = self._url_collection_params() or {} # path-params
        url = self._client.get_full_url(self.get_path('collection', **params))
        if kwargs:
            url += '?' + urlencode(kwargs)
        return url

    @abc.abstractmethod
    def _url_collection_params(self): # returns path-parameters, which are neccessary on collection-request
        pass
