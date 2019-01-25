class KeycloakClientError(Exception):
    def __init__(self, original_exc):
        """

        :param original_exc: Exception
        """
        self.original_exc = original_exc
        super(KeycloakClientError, self).__init__(*original_exc.args)

class KeycloakClientResponseError(KeycloakClientError):
    def __init__(self, response, **kwargs):
        self.response = response

        if hasattr(response, 'content') and response.content:
            import json
            content = json.loads(response.content)
            if 'errorMessage' in content:
                self.message = content['errorMessage']

        super(KeycloakClientResponseError, self).__init__(**kwargs)
