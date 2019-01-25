import abc
import json
import re
import six

__all__ = (
    'KeycloakAdmin',
    'KeycloakAdminBase',
    'KeycloakAdminBaseElement',
    'KeycloakAdminCollection',
)

PAT_VAR = re.compile('{([\_\w]+)}')

class KeycloakAdminBase(object):
    _admin = None
    _paths = None

    def __init__(self, admin, **kwargs):
        """
        :param keycloak.admin.KeycloakAdmin admin:
        """
        self._admin = admin

    def get_path(self, name, **kwargs):
        if self._paths is None:
            raise NotImplementedError()
        return self._paths[name].format(**kwargs)

    def get_path_dyn(self, name, **kwargs): # get path with dynamic path-arguments on member-vars
        if self._paths is None:
            raise NotImplementedError()

        path_args = {}
        for varname in PAT_VAR.findall(self._paths[name]):
            attr = '_%s' % varname
            if hasattr(self, attr):
                path_args[varname] = getattr(self, attr)
        path_args.update(kwargs)

        return self.get_path(name, **path_args)


class KeycloakAdminBaseElement(KeycloakAdminBase):
    _gen_payload_is_multiple = False
    _params = None
    _idents = {}

    @classmethod
    def gen_payload(cls, *args, **kwargs):
        if cls._gen_payload_is_multiple:
            return cls._gen_payload_multiple(*args, **kwargs)
        else:
            return cls._gen_payload_single(**kwargs)

    @classmethod
    def _gen_payload_multiple(cls, *args, **kwargs):
        res = []
        for data in args or [kwargs]:
            res.append(cls._gen_payload_single(**data))
        return res

    @classmethod
    def _gen_payload_single(cls, **kwargs):
        res = {}
        for key, val in kwargs.items():
            if cls._idents and key not in cls._idents:
                continue
            fkey = cls._idents[key] if key in cls._idents else key
            res[fkey] = cls._gen_payload_single_format(key, val)
        return res

    @classmethod
    def _gen_payload_single_format(cls, key, val):
        return val

    def __init__(self, params=None, *args, **kwargs):
        super(KeycloakAdminBaseElement, self).__init__(*args, **kwargs)
        self._params = params

    def __call__(self):
        if not self._params:
            self._params = self._admin.get(
                self._admin.get_full_url(self.get_path_dyn('single'))
            )
        return self._params

    def __repr__(self):
        params = [
            '%s=%s' % (k[1:], v)
            for k, v in self.__dict__.items()
            if v and k.startswith('_') and k not in ['_params', '_paths', '_admin', '_paths', '_idents']
        ]
        if self._idents and self._params:
            for name, key in self._idents.items():
                params.append('%s="%s"' % (name, self().get(key)))

        return '<%s(%s)>' % (self.__class__.__name__, " ".join(params))


    def __getattr__(self, attr):
        if attr in self._idents:
            # also provide property attributes for json payload elements
            # if mapping is defined in _idents
            json_key = self._idents[attr]
            if not self._params:
                self()
            if not json_key in self._params:
                raise ValueError('json data of \'%s\' does not contain \'%s\'' % (
                    self.__class__.__name__, json_key
                ))
            return self._params[json_key]

        else:
            raise AttributeError('\'%s\' object has no attribute \'%s\'%s' % (
                self.__class__.__name__, attr,
                self._idents and ', only [%s] additional avalaible from json payload' % (
                    ", ".join(self._idents.keys()), ) or ''
            ))

    def get(self):
        res = self()
        for key, kc_key in self._idents.items():
            res[key] = res.pop(kc_key) if kc_key in res else None
        return res

    def update(self, **kwargs):
        return self._admin.put(
            url=self._admin.get_full_url(self.get_path_dyn('single')),
            data=json.dumps(self.gen_payload(**kwargs))
        )

    def delete(self):
        return self._admin.delete(
            self._admin.get_full_url(self.get_path_dyn('single'))
        )


class KeycloakAdmin(object):
    _paths = {
        'root': '/'
    }
    _realm = None
    _response_headers = None # headers of last response
    _token = None

    def __init__(self, realm):
        """
        :param keycloak.realm.KeycloakRealm realm:
        """
        self._realm = realm

    @property
    def response_headers(self):
        return self._response_headers

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
        return Realms(admin=self)

    def post(self, url, data, headers=None, **kwargs):
        return self._req('post', url, headers, data)

    def put(self, url, data, headers=None, **kwargs):
        return self._req('put', url, headers, data)

    def get(self, url, headers=None, **kwargs):
        return self._req('get', url, headers)

    def delete(self, url, headers=None, data=None, **kwargs):
        return self._req('delete', url, headers, data)

    def _req(self, method, url, headers=None, data=None, **kwargs): # request & setting response-headers
        opts = dict(url=url, headers=self._add_auth_header(headers))
        if data is not None:
            opts['data'] = data
        res = getattr(self._realm.client, method)(**opts) # dynamic call
        self._response_headers = self._realm.client.response_headers
        return res

    def _add_auth_header(self, headers=None):
        if callable(self._token):
            token = self._token()
        else:
            token = self._token

        if token is None:
            raise Exception('No token stored in %s. You need to call %s.set_token with an valid access token/function first.' % (
                self.__class__.__name__, self.__class__.__name__
            ))

        headers = headers or {}
        headers['Authorization'] = "Bearer {}".format(token)
        headers['Content-Type'] = 'application/json'
        return headers


class KeycloakAdminCollection(KeycloakAdminBase):
    __metaclass__ = abc.ABCMeta
    _defaults_all_query = {} # default query-parameters
    _sort_col = None
    _sort_asc = True
    _itemclass = abc.ABCMeta


    def __iter__(self, *args, **kwargs):
        return self().__iter__(*args, **kwargs)

    def __getitem__(self, *args, **kwargs):
        return self().__getitem__(*args, **kwargs)

    def __len__(self):
        if self._paths.get('count'):
            return self.count()
        return self().__len__()

    def __call__(self, **kwargs):
        items = self.all(**kwargs)

        if isinstance(self._itemclass, dict):
            res = []
            for pos, itemclass in self._itemclass.items():
                subitems = items.get(pos, [])
                if isinstance(subitems, list):
                    for k in subitems:
                        res.append(itemclass(params=k, **self._url_item_params(pos, k)))
                elif isinstance(subitems, dict):
                    for k, v in subitems.items():
                        res.append(itemclass(**self._url_item_params(pos, v)))

            return res
        else:
            return [
                self._itemclass(params=k, **self._url_item_params(k))
                for k in items
            ]

    def __repr__(self):
        return '<%s ([%s])>' % (
            self.__class__.__name__,
            ", ".join([repr(k) for k in self()])
        )

    def all(self, **kwargs):
        query = self._defaults_all_query.copy()
        query.update(kwargs)
        return self._all_sorted(self._admin.get(self._url_collection(**query)))

    def all_on(self, col, sort=True, **kwargs):
        res = self.unsorted().all(**kwargs)
        if col is not None:
            res = [u[col] for u in res]
            if sort:
                res.sort(key=lambda v: v.lower()) # case insensitive sorting
        return res

    def count(self):
        if self._paths.get('count'):
            return self._admin.get(
                self._admin.get_full_url(self.get_path_dyn('count'))
            )
        raise AttributeError('_paths definition of "%s" does not contain "count"' % (
            self.__cls__.__name__
        ))


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
        url = self._admin.get_full_url(self.get_path_dyn(self._url_collection_path_name(), **params))
        if kwargs:
            url += '?' + six.moves.urllib.parse.urlencode(kwargs)
        return url

    @abc.abstractmethod
    def _url_item_params(self, item):
        return {}

    def _url_collection_params(self): # returns path-parameters, which are neccessary on collection-request
        pass

    def _url_collection_path_name(self): # can be overwritten, if other path-names should be used
        return 'collection'

    def create(self, return_id=False, *args, **kwargs):
        if isinstance(return_id, list): # TODO find a better way of taking multiple data-values
            args = return_id
            return_id = False
        res = self._admin.post(
            url=self._url_collection(),
            data=json.dumps(self._itemclass.gen_payload(*args, **kwargs))
        )
        if return_id:
            res = self._create_extract_id()
        return res

    def _create_extract_id(self):
        # extract id of created keycloak-object from location-url of response-headers
        # TODO only tested on creating an user; have to be also checked on other object-types
        url = self._url_collection()
        if self._admin.response_headers \
                and 'Location' in self._admin.response_headers \
                and re.match("^%s" % url, self._admin.response_headers['Location']):
            return re.sub("^%s" % url, '', self._admin.response_headers['Location']).strip('/')

    def delete(self, *args, **kwargs): # working only on requests with multiple data-structure
        if args and isinstance(args[0], list): # TODO find a better way of taking multiple data-values
            args = args[0]
        return self._admin.delete(
            url=self._url_collection(),
            data=json.dumps(self._itemclass.gen_payload(*args, **kwargs))
        )
