# coding: utf-8

# (C) Copyright IBM Corp. 2022.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# IBM OpenAPI SDK Code Generator Version: 3.60.2-95dc7721-20221102-203229

"""
With IBM Cloud® Secrets Manager, you can create, lease, and centrally manage secrets that
are used in IBM Cloud services or your custom-built applications. Secrets are stored in a
dedicated instance of Secrets Manager, which is built on open source HashiCorp Vault.

API Version: 1.0.0
See: https://cloud.ibm.com/docs/secrets-manager
"""

import json
from datetime import datetime
from enum import Enum
from typing import Dict, List

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_list, convert_model, datetime_to_string, string_to_datetime

from .common import get_sdk_headers


##############################################################################
# Service
##############################################################################

class SecretsManagerV1(BaseService):
    """The secrets-manager V1 service."""

    DEFAULT_SERVICE_URL = None
    DEFAULT_SERVICE_NAME = 'secrets_manager'

    @classmethod
    def new_instance(cls,
                     service_name: str = DEFAULT_SERVICE_NAME,
                     ) -> 'SecretsManagerV1':
        """
        Return a new client for the secrets-manager service using the specified
               parameters and external configuration.
        """
        authenticator = get_authenticator_from_environment(service_name)
        service = cls(
            authenticator
        )
        service.configure_service(service_name)
        return service

    def __init__(self,
                 authenticator: Authenticator = None,
                 ) -> None:
        """
        Construct a new client for the secrets-manager service.

        :param Authenticator authenticator: The authenticator specifies the authentication mechanism.
               Get up to date information from https://github.com/IBM/python-sdk-core/blob/main/README.md
               about initializing the authenticator of your choice.
        """
        BaseService.__init__(self,
                             service_url=self.DEFAULT_SERVICE_URL,
                             authenticator=authenticator)

    #########################
    # Secret groups
    #########################

    def create_secret_group(self,
                            metadata: 'CollectionMetadata',
                            resources: List['SecretGroupResource'],
                            **kwargs
                            ) -> DetailedResponse:
        """
        Create a secret group.

        Create a secret group that you can use to organize secrets and control who on your
        team has access to them.
        A successful request returns the ID value of the secret group, along with other
        metadata. To learn more about secret groups, check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-groups).

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretGroupResource] resources: A collection of resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='create_secret_group')
        headers.update(sdk_headers)

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/secret_groups'
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def list_secret_groups(self,
                           **kwargs
                           ) -> DetailedResponse:
        """
        List secret groups.

        List the secret groups that are available in your Secrets Manager instance.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='list_secret_groups')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/secret_groups'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def get_secret_group(self,
                         id: str,
                         **kwargs
                         ) -> DetailedResponse:
        """
        Get a secret group.

        Get the metadata of an existing secret group by specifying the ID of the group.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_group')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_secret_group_metadata(self,
                                     id: str,
                                     metadata: 'CollectionMetadata',
                                     resources: List['SecretGroupMetadataUpdatable'],
                                     **kwargs
                                     ) -> DetailedResponse:
        """
        Update a secret group.

        Update the metadata of an existing secret group, such as its name or description.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretGroupMetadataUpdatable] resources: A collection of
               resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        if not id:
            raise ValueError('id must be provided')
        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret_group_metadata')
        headers.update(sdk_headers)

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def delete_secret_group(self,
                            id: str,
                            **kwargs
                            ) -> DetailedResponse:
        """
        Delete a secret group.

        Delete a secret group by specifying the ID of the secret group.
        **Note:** To delete a secret group, it must be empty. If you need to remove a
        secret group that contains secrets, you must first [delete the
        secrets](#delete-secret) that are associated with the group.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_secret_group')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    #########################
    # Secrets
    #########################

    def create_secret(self,
                      secret_type: str,
                      metadata: 'CollectionMetadata',
                      resources: List['SecretResource'],
                      **kwargs
                      ) -> DetailedResponse:
        """
        Create a secret.

        Create a secret or import an existing value that you can use to access or
        authenticate to a protected resource.
        Use this method to either generate or import an existing secret, such as an
        arbitrary value or a TLS certificate, that you can manage in your Secrets Manager
        service instance. A successful request stores the secret in your dedicated
        instance based on the secret type and data that you specify. The response returns
        the ID value of the secret, along with other metadata.
        To learn more about the types of secrets that you can create with Secrets Manager,
        check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-what-is-secret).

        :param str secret_type: The secret type.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretResource] resources: A collection of resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateSecret` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='create_secret')
        headers.update(sdk_headers)

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def list_secrets(self,
                     secret_type: str,
                     *,
                     limit: int = None,
                     offset: int = None,
                     **kwargs
                     ) -> DetailedResponse:
        """
        List secrets by type.

        List the secrets in your Secrets Manager instance based on the type that you
        specify.

        :param str secret_type: The secret type.
        :param int limit: (optional) The number of secrets to retrieve. By default,
               list operations return the first 200 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 secrets in your instance, and you want to
               retrieve only the first 5 secrets, use
               `../secrets/{secret_type}?limit=5`.
        :param int offset: (optional) The number of secrets to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 secrets in your instance, and you want to
               retrieve secrets 26 through 50, use
               `..?offset=25&limit=25`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecrets` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='list_secrets')
        headers.update(sdk_headers)

        params = {
            'limit': limit,
            'offset': offset
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    def list_all_secrets(self,
                         *,
                         limit: int = None,
                         offset: int = None,
                         search: str = None,
                         sort_by: str = None,
                         groups: List[str] = None,
                         **kwargs
                         ) -> DetailedResponse:
        """
        List all secrets.

        List all of the secrets in your Secrets Manager instance.

        :param int limit: (optional) The number of secrets to retrieve. By default,
               list operations return the first 200 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 secrets in your instance, and you want to
               retrieve only the first 5 secrets, use
               `../secrets/{secret_type}?limit=5`.
        :param int offset: (optional) The number of secrets to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 secrets in your instance, and you want to
               retrieve secrets 26 through 50, use
               `..?offset=25&limit=25`.
        :param str search: (optional) Filter secrets that contain the specified
               string. The fields that are searched include: id, name, description,
               labels, secret_type.
               **Usage:** If you want to list only the secrets that contain the string
               "text", use
               `../secrets/{secret_type}?search=text`.
        :param str sort_by: (optional) Sort a list of secrets by the specified
               field.
               **Usage:** To sort a list of secrets by their creation date, use
               `../secrets/{secret_type}?sort_by=creation_date`.
        :param List[str] groups: (optional) Filter secrets by groups.
               You can apply multiple filters by using a comma-separated list of secret
               group IDs. If you need to filter secrets that are in the default secret
               group, use the `default` keyword.
               **Usage:** To retrieve a list of secrets that are associated with an
               existing secret group or the default group, use
               `..?groups={secret_group_ID},default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecrets` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='list_all_secrets')
        headers.update(sdk_headers)

        params = {
            'limit': limit,
            'offset': offset,
            'search': search,
            'sort_by': sort_by,
            'groups': convert_list(groups)
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/secrets'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    def get_secret(self,
                   secret_type: str,
                   id: str,
                   **kwargs
                   ) -> DetailedResponse:
        """
        Get a secret.

        Get a secret and its details by specifying the ID of the secret.
        A successful request returns the secret data that is associated with your secret,
        along with other metadata. To view only the details of a specified secret without
        retrieving its value, use the [Get secret metadata](#get-secret-metadata) method.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecret` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_secret(self,
                      secret_type: str,
                      id: str,
                      action: str,
                      *,
                      secret_action: 'SecretAction' = None,
                      **kwargs
                      ) -> DetailedResponse:
        """
        Invoke an action on a secret.

        Invoke an action on a specified secret. This method supports the following
        actions:
        - `rotate`: Replace the value of a secret.
        - `restore`: Restore a previous version of an `iam_credentials` secret.
        - `revoke`: Revoke a private certificate.
        - `delete_credentials`: Delete the API key that is associated with an
        `iam_credentials` secret.
        - `validate_dns_challenge`: Validate challenges for a public certificate that is
        ordered with a manual DNS provider.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str action: The action to perform on the specified secret.
        :param SecretAction secret_action: (optional) The properties to update for
               the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecret` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not action:
            raise ValueError('action must be provided')
        if secret_action is not None and isinstance(secret_action, SecretAction):
            secret_action = convert_model(secret_action)
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret')
        headers.update(sdk_headers)

        params = {
            'action': action
        }

        data = json.dumps(secret_action)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       params=params,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def delete_secret(self,
                      secret_type: str,
                      id: str,
                      **kwargs
                      ) -> DetailedResponse:
        """
        Delete a secret.

        Delete a secret by specifying the ID of the secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_secret')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def list_secret_versions(self,
                             secret_type: str,
                             id: str,
                             **kwargs
                             ) -> DetailedResponse:
        """
        List versions of a secret.

        List the versions of a secret.
        A successful request returns the list of the versions along with the metadata of
        each version.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecretVersions` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='list_secret_versions')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/versions'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def get_secret_version(self,
                           secret_type: str,
                           id: str,
                           version_id: str,
                           **kwargs
                           ) -> DetailedResponse:
        """
        Get a version of a secret.

        Get a version of a secret by specifying the ID of the version or the alias
        `previous`.
        A successful request returns the secret data that is associated with the specified
        version of your secret, along with other metadata.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretVersion` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_version')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/versions/{version_id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_secret_version(self,
                              secret_type: str,
                              id: str,
                              version_id: str,
                              action: str,
                              **kwargs
                              ) -> DetailedResponse:
        """
        Invoke an action on a version of a secret.

        Invoke an action on a specified version of a secret. This method supports the
        following actions:
        - `revoke`: Revoke a version of a private certificate.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param str action: The action to perform on the specified secret version.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecret` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        if not action:
            raise ValueError('action must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret_version')
        headers.update(sdk_headers)

        params = {
            'action': action
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/versions/{version_id}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    def get_secret_version_metadata(self,
                                    secret_type: str,
                                    id: str,
                                    version_id: str,
                                    **kwargs
                                    ) -> DetailedResponse:
        """
        Get the metadata of a secret version.

        Get the metadata of a secret version by specifying the ID of the version or the
        alias `previous`.
        A successful request returns the metadata that is associated with the specified
        version of your secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretVersionMetadata` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_version_metadata')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/versions/{version_id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_secret_version_metadata(self,
                                       secret_type: str,
                                       id: str,
                                       version_id: str,
                                       metadata: 'CollectionMetadata',
                                       resources: List['UpdateSecretVersionMetadata'],
                                       **kwargs
                                       ) -> DetailedResponse:
        """
        Update the metadata of a secret version.

        Update the metadata of a secret version, such as `version_custom_metadata`.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[UpdateSecretVersionMetadata] resources: A collection of
               resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretVersionMetadata` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret_version_metadata')
        headers.update(sdk_headers)

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/versions/{version_id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_secret_metadata(self,
                            secret_type: str,
                            id: str,
                            **kwargs
                            ) -> DetailedResponse:
        """
        Get the metadata of a secret.

        Get the details of a secret by specifying its ID.
        A successful request returns only metadata about the secret, such as its name and
        creation date. To retrieve the value of a secret, use the [Get a
        secret](#get-secret) or [Get a version of a secret](#get-secret-version) methods.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretMetadataRequest` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_metadata')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_secret_metadata(self,
                               secret_type: str,
                               id: str,
                               metadata: 'CollectionMetadata',
                               resources: List['SecretMetadata'],
                               **kwargs
                               ) -> DetailedResponse:
        """
        Update secret metadata.

        Update the metadata of a secret, such as its name or description.
        To update the actual contents of a secret, rotate the secret by using the [Invoke
        an action on a secret](#update-secret) method.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretMetadata] resources: A collection of resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretMetadataRequest` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret_metadata')
        headers.update(sdk_headers)

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    #########################
    # Locks
    #########################

    def get_locks(self,
                  secret_type: str,
                  id: str,
                  *,
                  limit: int = None,
                  offset: int = None,
                  search: str = None,
                  **kwargs
                  ) -> DetailedResponse:
        """
        List secret locks.

        List the locks that are associated with a specified secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param int limit: (optional) The number of locks to retrieve. By default,
               list operations return the first 25 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 locks associated with your secret, and you want
               to retrieve only the first 5 locks, use
               `..?limit=5`.
        :param int offset: (optional) The number of locks to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 locks on your secret, and you want to retrieve
               locks 26 through 50, use
               `..?offset=25&limit=25`.
        :param str search: (optional) Filter locks that contain the specified
               string in the field "name".
               **Usage:** If you want to list only the locks that contain the string
               "text" in the field "name", use
               `..?search=text`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_locks')
        headers.update(sdk_headers)

        params = {
            'limit': limit,
            'offset': offset,
            'search': search
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    def lock_secret(self,
                    secret_type: str,
                    id: str,
                    *,
                    locks: List['LockSecretBodyLocksItem'] = None,
                    mode: str = None,
                    **kwargs
                    ) -> DetailedResponse:
        """
        Lock a secret.

        Create a lock on the current version of a secret.
        A lock can be used to prevent a secret from being deleted or modified while it's
        in use by your applications. A successful request attaches a new lock to your
        secret, or replaces a lock of the same name if it already exists. Additionally,
        you can use this method to clear any matching locks on a secret by using one of
        the following optional lock modes:
        - `exclusive`: Removes any other locks with matching names if they are found in
        the previous version of the secret.
        - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the data
        of the previous secret version if it doesn't have any locks.
        For more information about locking secrets, check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-locks).

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param List[LockSecretBodyLocksItem] locks: (optional) The lock data to be
               attached to a secret version.
        :param str mode: (optional) An optional lock mode. At lock creation, you
               can set one of the following modes to clear any matching locks on a secret
               version. Note: When you are locking the `previous` version, the mode
               parameter is ignored.
               - `exclusive`: Removes any other locks with matching names if they are
               found in the previous version of the secret.
               - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the
               data of the previous secret version if it doesn't have any locks.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if locks is not None:
            locks = [convert_model(x) for x in locks]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='lock_secret')
        headers.update(sdk_headers)

        params = {
            'mode': mode
        }

        data = {
            'locks': locks
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}/lock'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       params=params,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def unlock_secret(self,
                      secret_type: str,
                      id: str,
                      *,
                      locks: List[str] = None,
                      **kwargs
                      ) -> DetailedResponse:
        """
        Unlock a secret.

        Delete one or more locks that are associated with the current version of a secret.
        A successful request deletes the locks that you specify. To remove all locks, you
        can pass `{"locks": ["*"]}` in in the request body. Otherwise, specify the names
        of the locks that you want to delete. For example, `{"locks":
        ["lock1", "lock2"]}`.
        **Note:** A secret is considered unlocked and able to be revoked or deleted only
        after all of its locks are removed. To understand whether a secret contains locks,
        check the `locks_total` field that is returned as part of the metadata of your
        secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param List[str] locks: (optional) A comma-separated list of locks to
               delete.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='unlock_secret')
        headers.update(sdk_headers)

        data = {
            'locks': locks
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}/unlock'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_secret_version_locks(self,
                                 secret_type: str,
                                 id: str,
                                 version_id: str,
                                 *,
                                 limit: int = None,
                                 offset: int = None,
                                 search: str = None,
                                 **kwargs
                                 ) -> DetailedResponse:
        """
        List secret version locks.

        List the locks that are associated with a specified secret version.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param int limit: (optional) The number of locks to retrieve. By default,
               list operations return the first 25 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 locks associated with your secret, and you want
               to retrieve only the first 5 locks, use
               `..?limit=5`.
        :param int offset: (optional) The number of locks to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 locks on your secret, and you want to retrieve
               locks 26 through 50, use
               `..?offset=25&limit=25`.
        :param str search: (optional) Filter locks that contain the specified
               string in the field "name".
               **Usage:** If you want to list only the locks that contain the string
               "text" in the field "name", use
               `..?search=text`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_version_locks')
        headers.update(sdk_headers)

        params = {
            'limit': limit,
            'offset': offset,
            'search': search
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}/versions/{version_id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    def lock_secret_version(self,
                            secret_type: str,
                            id: str,
                            version_id: str,
                            *,
                            locks: List['LockSecretBodyLocksItem'] = None,
                            mode: str = None,
                            **kwargs
                            ) -> DetailedResponse:
        """
        Lock a secret version.

        Create a lock on the specified version of a secret.
        A lock can be used to prevent a secret from being deleted or modified while it's
        in use by your applications. A successful request attaches a new lock to the
        specified version, or replaces a lock of the same name if it already exists.
        Additionally, you can use this method to clear any matching locks on a secret
        version by using one of the following optional lock modes:
        - `exclusive`: Removes any other locks with matching names if they are found in
        the previous version of the secret.
        - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the data
        of the previous secret version if it doesn't have any locks.
        For more information about locking secrets, check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-locks).

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param List[LockSecretBodyLocksItem] locks: (optional) The lock data to be
               attached to a secret version.
        :param str mode: (optional) An optional lock mode. At lock creation, you
               can set one of the following modes to clear any matching locks on a secret
               version. Note: When you are locking the `previous` version, the mode
               parameter is ignored.
               - `exclusive`: Removes any other locks with matching names if they are
               found in the previous version of the secret.
               - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the
               data of the previous secret version if it doesn't have any locks.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        if locks is not None:
            locks = [convert_model(x) for x in locks]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='lock_secret_version')
        headers.update(sdk_headers)

        params = {
            'mode': mode
        }

        data = {
            'locks': locks
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}/versions/{version_id}/lock'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       params=params,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def unlock_secret_version(self,
                              secret_type: str,
                              id: str,
                              version_id: str,
                              *,
                              locks: List[str] = None,
                              **kwargs
                              ) -> DetailedResponse:
        """
        Unlock a secret version.

        Delete one or more locks that are associated with the specified secret version.
        A successful request deletes the locks that you specify. To remove all locks, you
        can pass `{"locks": ["*"]}` in in the request body. Otherwise, specify the names
        of the locks that you want to delete. For example, `{"locks":
        ["lock-1", "lock-2"]}`.
        **Note:** A secret is considered unlocked and able to be revoked or deleted only
        after all of its locks are removed. To understand whether a secret contains locks,
        check the `locks_total` field that is returned as part of the metadata of your
        secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param List[str] locks: (optional) A comma-separated list of locks to
               delete.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretLocks` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if not version_id:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='unlock_secret_version')
        headers.update(sdk_headers)

        data = {
            'locks': locks
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id', 'version_id']
        path_param_values = self.encode_path_vars(secret_type, id, version_id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/locks/{secret_type}/{id}/versions/{version_id}/unlock'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def list_instance_secrets_locks(self,
                                    *,
                                    limit: int = None,
                                    offset: int = None,
                                    search: str = None,
                                    groups: List[str] = None,
                                    **kwargs
                                    ) -> DetailedResponse:
        """
        List all secrets and locks.

        List the lock details that are associated with all secrets in your Secrets Manager
        instance.

        :param int limit: (optional) The number of secrets with associated locks to
               retrieve. By default, list operations return the first 25 items. To
               retrieve a different set of items, use `limit` with `offset` to page
               through your available resources.
               **Usage:** If you have 20 secrets in your instance, and you want to
               retrieve only the first 5, use
               `..?limit=5`.
        :param int offset: (optional) The number of secrets to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 secrets in your instance, and you want to
               retrieve secrets 26 through 50, use
               `..?offset=25&limit=25`.
        :param str search: (optional) Filter locks that contain the specified
               string in the field "name".
               **Usage:** If you want to list only the locks that contain the string
               "text" in the field "name", use
               `..?search=text`.
        :param List[str] groups: (optional) Filter secrets by groups.
               You can apply multiple filters by using a comma-separated list of secret
               group IDs. If you need to filter secrets that are in the default secret
               group, use the `default` keyword.
               **Usage:** To retrieve a list of secrets that are associated with an
               existing secret group or the default group, use
               `..?groups={secret_group_ID},default`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetInstanceLocks` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='list_instance_secrets_locks')
        headers.update(sdk_headers)

        params = {
            'limit': limit,
            'offset': offset,
            'search': search,
            'groups': convert_list(groups)
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/locks'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    #########################
    # Policies
    #########################

    def put_policy(self,
                   secret_type: str,
                   id: str,
                   metadata: 'CollectionMetadata',
                   resources: List['SecretPolicyRotation'],
                   *,
                   policy: str = None,
                   **kwargs
                   ) -> DetailedResponse:
        """
        Set secret policies.

        Create or update one or more policies, such as an [automatic rotation
        policy](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-automatic-rotation),
        for the specified secret. To remove a policy, keep the resources block empty.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretPolicyRotation] resources: A collection of resources.
        :param str policy: (optional) The type of policy that is associated with
               the specified secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPolicies` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        if metadata is None:
            raise ValueError('metadata must be provided')
        if resources is None:
            raise ValueError('resources must be provided')
        metadata = convert_model(metadata)
        resources = [convert_model(x) for x in resources]
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='put_policy')
        headers.update(sdk_headers)

        params = {
            'policy': policy
        }

        data = {
            'metadata': metadata,
            'resources': resources
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/policies'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       params=params,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_policy(self,
                   secret_type: str,
                   id: str,
                   *,
                   policy: str = None,
                   **kwargs
                   ) -> DetailedResponse:
        """
        List secret policies.

        List the rotation policies that are associated with a specified secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str policy: (optional) The type of policy that is associated with
               the specified secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPolicies` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not id:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_policy')
        headers.update(sdk_headers)

        params = {
            'policy': policy
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/policies'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request, **kwargs)
        return response

    #########################
    # Config
    #########################

    def put_config(self,
                   secret_type: str,
                   engine_config: 'EngineConfig',
                   **kwargs
                   ) -> DetailedResponse:
        """
        Set the configuration of a secret type.

        Set the configuration for the specified secret type.
        Use this method to configure the IAM credentials (`iam_credentials`) engine for
        your service instance. Looking to order or generate certificates? To configure the
        public certificates (`public_cert`) or  private certificates (`private_cert`)
        engines, use the [Add a configuration](#create_config_element) method.

        :param str secret_type: The secret type.
        :param EngineConfig engine_config: Properties to update for a secrets
               engine.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if engine_config is None:
            raise ValueError('engine_config must be provided')
        if isinstance(engine_config, EngineConfig):
            engine_config = convert_model(engine_config)
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='put_config')
        headers.update(sdk_headers)

        data = json.dumps(engine_config)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_config(self,
                   secret_type: str,
                   **kwargs
                   ) -> DetailedResponse:
        """
        Get the configuration of a secret type.

        Get the configuration that is associated with the specified secret type.

        :param str secret_type: The secret type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetConfig` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def create_config_element(self,
                              secret_type: str,
                              config_element: str,
                              name: str,
                              type: str,
                              config: 'ConfigElementDefConfig',
                              **kwargs
                              ) -> DetailedResponse:
        """
        Add a configuration.

        Add a configuration element to the specified secret type.
        Use this method to define the configurations that are required to enable the
        public certificates (`public_cert`) and private certificates (`private_cert`)
        engines.
        You can add multiple configurations for your instance as follows:
        - Up to 10 public certificate authority configurations
        - Up to 10 DNS provider configurations
        - Up to 10 private root certificate authority configurations
        - Up to 10 private intermediate certificate authority configurations
        - Up to 10 certificate templates.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element to define or manage.
        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param ConfigElementDefConfig config: The configuration to define for the
               specified secret type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        if name is None:
            raise ValueError('name must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if config is None:
            raise ValueError('config must be provided')
        config = convert_model(config)
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='create_config_element')
        headers.update(sdk_headers)

        data = {
            'name': name,
            'type': type,
            'config': config
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'config_element']
        path_param_values = self.encode_path_vars(secret_type, config_element)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_config_elements(self,
                            secret_type: str,
                            config_element: str,
                            **kwargs
                            ) -> DetailedResponse:
        """
        List configurations.

        List the configuration elements that are associated with a specified secret type.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element to define or manage.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetConfigElements` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config_elements')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'config_element']
        path_param_values = self.encode_path_vars(secret_type, config_element)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def get_config_element(self,
                           secret_type: str,
                           config_element: str,
                           config_name: str,
                           **kwargs
                           ) -> DetailedResponse:
        """
        Get a configuration.

        Get the details of a specific configuration that is associated with a secret type.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element to define or manage.
        :param str config_name: The name of your configuration.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        if not config_name:
            raise ValueError('config_name must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config_element')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'config_element', 'config_name']
        path_param_values = self.encode_path_vars(secret_type, config_element, config_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}/{config_name}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def update_config_element(self,
                              secret_type: str,
                              config_element: str,
                              config_name: str,
                              type: str,
                              config: dict,
                              **kwargs
                              ) -> DetailedResponse:
        """
        Update a configuration.

        Update a configuration element that is associated with the specified secret type.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element to define or manage.
        :param str config_name: The name of your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param dict config: Properties that describe a configuration, which depends
               on type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        if not config_name:
            raise ValueError('config_name must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if config is None:
            raise ValueError('config must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_config_element')
        headers.update(sdk_headers)

        data = {
            'type': type,
            'config': config
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'config_element', 'config_name']
        path_param_values = self.encode_path_vars(secret_type, config_element, config_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}/{config_name}'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def action_on_config_element(self,
                                 secret_type: str,
                                 config_element: str,
                                 config_name: str,
                                 action: str,
                                 *,
                                 config: 'ConfigAction' = None,
                                 **kwargs
                                 ) -> DetailedResponse:
        """
        Invoke an action on a configuration.

        Invoke an action on a specified configuration element. This method supports the
        following actions:
        - `sign_intermediate`: Sign an intermediate certificate authority.
        - `sign_csr`: Sign a certificate signing request.
        - `set_signed`: Set a signed intermediate certificate authority.
        - `revoke`: Revoke an internally signed intermediate certificate authority
        certificate.
        - `rotate_crl`: Rotate the certificate revocation list (CRL) of an intermediate
        certificate authority.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element on which the action is
               applied.
        :param str config_name: The name of the certificate authority.
        :param str action: The action to perform on the specified configuration
               element.
        :param ConfigAction config: (optional) Properties that describe an action
               on a configuration element.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ConfigElementActionResult` object
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        if not config_name:
            raise ValueError('config_name must be provided')
        if not action:
            raise ValueError('action must be provided')
        if config is not None:
            config = convert_model(config)
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='action_on_config_element')
        headers.update(sdk_headers)

        params = {
            'action': action
        }

        data = {
            'config': config
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'config_element', 'config_name']
        path_param_values = self.encode_path_vars(secret_type, config_element, config_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}/{config_name}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       params=params,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def delete_config_element(self,
                              secret_type: str,
                              config_element: str,
                              config_name: str,
                              **kwargs
                              ) -> DetailedResponse:
        """
        Delete a configuration.

        Delete a configuration element from the specified secret type.

        :param str secret_type: The secret type.
        :param str config_element: The configuration element to define or manage.
        :param str config_name: The name of your configuration.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if not secret_type:
            raise ValueError('secret_type must be provided')
        if not config_element:
            raise ValueError('config_element must be provided')
        if not config_name:
            raise ValueError('config_name must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_config_element')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        path_param_keys = ['secret_type', 'config_element', 'config_name']
        path_param_values = self.encode_path_vars(secret_type, config_element, config_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}/{config_name}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    #########################
    # Notifications
    #########################

    def create_notifications_registration(self,
                                          event_notifications_instance_crn: str,
                                          event_notifications_source_name: str,
                                          *,
                                          event_notifications_source_description: str = None,
                                          **kwargs
                                          ) -> DetailedResponse:
        """
        Register with Event Notifications.

        Create a registration between a Secrets Manager instance and [Event
        Notifications](https://cloud.ibm.com/apidocs/event-notifications).
        A successful request adds Secrets Manager as a source that you can reference from
        your Event Notifications instance. For more information about enabling
        notifications for Secrets Manager, check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-event-notifications).

        :param str event_notifications_instance_crn: The Cloud Resource Name (CRN)
               of the connected Event Notifications instance.
        :param str event_notifications_source_name: The name that is displayed as a
               source in your Event Notifications instance.
        :param str event_notifications_source_description: (optional) An optional
               description for the source in your Event Notifications instance.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetNotificationsSettings` object
        """

        if event_notifications_instance_crn is None:
            raise ValueError('event_notifications_instance_crn must be provided')
        if event_notifications_source_name is None:
            raise ValueError('event_notifications_source_name must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='create_notifications_registration')
        headers.update(sdk_headers)

        data = {
            'event_notifications_instance_crn': event_notifications_instance_crn,
            'event_notifications_source_name': event_notifications_source_name,
            'event_notifications_source_description': event_notifications_source_description
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/notifications/registration'
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request, **kwargs)
        return response

    def get_notifications_registration(self,
                                       **kwargs
                                       ) -> DetailedResponse:
        """
        Get Event Notifications registration details.

        Get the details of an existing registration between a Secrets Manager instance and
        Event Notifications.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetNotificationsSettings` object
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_notifications_registration')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']
        headers['Accept'] = 'application/json'

        url = '/api/v1/notifications/registration'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def delete_notifications_registration(self,
                                          **kwargs
                                          ) -> DetailedResponse:
        """
        Unregister from Event Notifications.

        Delete a registration between a Secrets Manager instance and Event Notifications.
        A successful request removes your Secrets Manager instance as a source in Event
        Notifications.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_notifications_registration')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/api/v1/notifications/registration'
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response

    def send_test_notification(self,
                               **kwargs
                               ) -> DetailedResponse:
        """
        Send a test event.

        Send a test event from a Secrets Manager instance to a configured [Event
        Notifications](https://cloud.ibm.com/apidocs/event-notifications) instance.
        A successful request sends a test event to the Event Notifications instance. For
        more information about enabling notifications for Secrets Manager, check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-event-notifications).

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='send_test_notification')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
            del kwargs['headers']

        url = '/api/v1/notifications/test'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request, **kwargs)
        return response


class CreateSecretEnums:
    """
    Enums for create_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class ListSecretsEnums:
    """
    Enums for list_secrets parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class ListAllSecretsEnums:
    """
    Enums for list_all_secrets parameters.
    """

    class SortBy(str, Enum):
        """
        Sort a list of secrets by the specified field.
        **Usage:** To sort a list of secrets by their creation date, use
        `../secrets/{secret_type}?sort_by=creation_date`.
        """
        ID = 'id'
        CREATION_DATE = 'creation_date'
        EXPIRATION_DATE = 'expiration_date'
        SECRET_TYPE = 'secret_type'
        NAME = 'name'


class GetSecretEnums:
    """
    Enums for get_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class UpdateSecretEnums:
    """
    Enums for update_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'

    class Action(str, Enum):
        """
        The action to perform on the specified secret.
        """
        ROTATE = 'rotate'
        RESTORE = 'restore'
        REVOKE = 'revoke'
        DELETE_CREDENTIALS = 'delete_credentials'
        VALIDATE_DNS_CHALLENGE = 'validate_dns_challenge'


class DeleteSecretEnums:
    """
    Enums for delete_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class ListSecretVersionsEnums:
    """
    Enums for list_secret_versions parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class GetSecretVersionEnums:
    """
    Enums for get_secret_version parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class UpdateSecretVersionEnums:
    """
    Enums for update_secret_version parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PRIVATE_CERT = 'private_cert'

    class Action(str, Enum):
        """
        The action to perform on the specified secret version.
        """
        REVOKE = 'revoke'


class GetSecretVersionMetadataEnums:
    """
    Enums for get_secret_version_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class UpdateSecretVersionMetadataEnums:
    """
    Enums for update_secret_version_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class GetSecretMetadataEnums:
    """
    Enums for get_secret_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class UpdateSecretMetadataEnums:
    """
    Enums for update_secret_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class GetLocksEnums:
    """
    Enums for get_locks parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class LockSecretEnums:
    """
    Enums for lock_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'

    class Mode(str, Enum):
        """
        An optional lock mode. At lock creation, you can set one of the following modes to
        clear any matching locks on a secret version. Note: When you are locking the
        `previous` version, the mode parameter is ignored.
        - `exclusive`: Removes any other locks with matching names if they are found in
        the previous version of the secret.
        - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the data
        of the previous secret version if it doesn't have any locks.
        """
        EXCLUSIVE = 'exclusive'
        EXCLUSIVE_DELETE = 'exclusive_delete'


class UnlockSecretEnums:
    """
    Enums for unlock_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class GetSecretVersionLocksEnums:
    """
    Enums for get_secret_version_locks parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class LockSecretVersionEnums:
    """
    Enums for lock_secret_version parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'

    class Mode(str, Enum):
        """
        An optional lock mode. At lock creation, you can set one of the following modes to
        clear any matching locks on a secret version. Note: When you are locking the
        `previous` version, the mode parameter is ignored.
        - `exclusive`: Removes any other locks with matching names if they are found in
        the previous version of the secret.
        - `exclusive_delete`: Same as `exclusive`, but also permanently deletes the data
        of the previous secret version if it doesn't have any locks.
        """
        EXCLUSIVE = 'exclusive'
        EXCLUSIVE_DELETE = 'exclusive_delete'


class UnlockSecretVersionEnums:
    """
    Enums for unlock_secret_version parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        USERNAME_PASSWORD = 'username_password'
        KV = 'kv'


class PutPolicyEnums:
    """
    Enums for put_policy parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified secret.
        """
        ROTATION = 'rotation'


class GetPolicyEnums:
    """
    Enums for get_policy parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified secret.
        """
        ROTATION = 'rotation'


class PutConfigEnums:
    """
    Enums for put_config parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        IAM_CREDENTIALS = 'iam_credentials'


class GetConfigEnums:
    """
    Enums for get_config parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        IAM_CREDENTIALS = 'iam_credentials'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'


class CreateConfigElementEnums:
    """
    Enums for create_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element to define or manage.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'
        CERTIFICATE_TEMPLATES = 'certificate_templates'


class GetConfigElementsEnums:
    """
    Enums for get_config_elements parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element to define or manage.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'
        CERTIFICATE_TEMPLATES = 'certificate_templates'


class GetConfigElementEnums:
    """
    Enums for get_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element to define or manage.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'
        CERTIFICATE_TEMPLATES = 'certificate_templates'


class UpdateConfigElementEnums:
    """
    Enums for update_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element to define or manage.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'
        CERTIFICATE_TEMPLATES = 'certificate_templates'


class ActionOnConfigElementEnums:
    """
    Enums for action_on_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element on which the action is applied.
        """
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'

    class Action(str, Enum):
        """
        The action to perform on the specified configuration element.
        """
        SIGN_INTERMEDIATE = 'sign_intermediate'
        SIGN_CSR = 'sign_csr'
        SET_SIGNED = 'set_signed'
        REVOKE = 'revoke'
        ROTATE_CRL = 'rotate_crl'


class DeleteConfigElementEnums:
    """
    Enums for delete_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'

    class ConfigElement(str, Enum):
        """
        The configuration element to define or manage.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'
        ROOT_CERTIFICATE_AUTHORITIES = 'root_certificate_authorities'
        INTERMEDIATE_CERTIFICATE_AUTHORITIES = 'intermediate_certificate_authorities'
        CERTIFICATE_TEMPLATES = 'certificate_templates'


##############################################################################
# Models
##############################################################################


class CertificateSecretData():
    """
    The data that is associated with the secret version. The data object contains the
    following fields:
    - `certificate`: The contents of the certificate.
    - `private_key`: The private key that is associated with the certificate.
    - `intermediate`: The intermediate certificate that is associated with the
    certificate.

    """

    def __init__(self,
                 **kwargs) -> None:
        """
        Initialize a CertificateSecretData object.

        :param **kwargs: (optional) Any additional properties.
        """
        for _key, _value in kwargs.items():
            setattr(self, _key, _value)

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretData':
        """Initialize a CertificateSecretData object from a json dictionary."""
        return cls(**_dict)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        return vars(self)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def get_properties(self) -> Dict:
        """Return a dictionary of arbitrary properties from this instance of CertificateSecretData"""
        _dict = {}

        for _key in [k for k in vars(self).keys()]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def set_properties(self, _dict: dict):
        """Set a dictionary of arbitrary properties to this instance of CertificateSecretData"""
        for _key in [k for k in vars(self).keys()]:
            delattr(self, _key)

        for _key, _value in _dict.items():
            setattr(self, _key, _value)

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretData') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretData') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CertificateTemplatesConfigItem():
    """
    Certificate templates configuration.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    :attr CertificateTemplateConfig config: (optional) Properties that describe a
          certificate template. You can use a certificate template to control the
          parameters that
          are applied to your issued private certificates. For more information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-certificate-templates).
    """

    def __init__(self,
                 name: str,
                 type: str,
                 *,
                 config: 'CertificateTemplateConfig' = None) -> None:
        """
        Initialize a CertificateTemplatesConfigItem object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param CertificateTemplateConfig config: (optional) Properties that
               describe a certificate template. You can use a certificate template to
               control the parameters that
               are applied to your issued private certificates. For more information, see
               the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-certificate-templates).
        """
        self.name = name
        self.type = type
        self.config = config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateTemplatesConfigItem':
        """Initialize a CertificateTemplatesConfigItem object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in CertificateTemplatesConfigItem JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in CertificateTemplatesConfigItem JSON')
        if 'config' in _dict:
            args['config'] = CertificateTemplateConfig.from_dict(_dict.get('config'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateTemplatesConfigItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'config') and self.config is not None:
            if isinstance(self.config, dict):
                _dict['config'] = self.config
            else:
                _dict['config'] = self.config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateTemplatesConfigItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateTemplatesConfigItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateTemplatesConfigItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class ChallengeResource():
    """
    Properties that describe a challenge.

    :attr str domain: (optional) The challenge domain.
    :attr datetime expiration: (optional) The challenge expiration date. The date
          format follows RFC 3339.
    :attr str status: (optional) The challenge status.
    :attr str txt_record_name: (optional) The txt_record_name.
    :attr str txt_record_value: (optional) The txt_record_value.
    """

    def __init__(self,
                 *,
                 domain: str = None,
                 expiration: datetime = None,
                 status: str = None,
                 txt_record_name: str = None,
                 txt_record_value: str = None) -> None:
        """
        Initialize a ChallengeResource object.

        """
        self.domain = domain
        self.expiration = expiration
        self.status = status
        self.txt_record_name = txt_record_name
        self.txt_record_value = txt_record_value

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ChallengeResource':
        """Initialize a ChallengeResource object from a json dictionary."""
        args = {}
        if 'domain' in _dict:
            args['domain'] = _dict.get('domain')
        if 'expiration' in _dict:
            args['expiration'] = string_to_datetime(_dict.get('expiration'))
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'txt_record_name' in _dict:
            args['txt_record_name'] = _dict.get('txt_record_name')
        if 'txt_record_value' in _dict:
            args['txt_record_value'] = _dict.get('txt_record_value')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ChallengeResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'domain') and getattr(self, 'domain') is not None:
            _dict['domain'] = getattr(self, 'domain')
        if hasattr(self, 'expiration') and getattr(self, 'expiration') is not None:
            _dict['expiration'] = datetime_to_string(getattr(self, 'expiration'))
        if hasattr(self, 'status') and getattr(self, 'status') is not None:
            _dict['status'] = getattr(self, 'status')
        if hasattr(self, 'txt_record_name') and getattr(self, 'txt_record_name') is not None:
            _dict['txt_record_name'] = getattr(self, 'txt_record_name')
        if hasattr(self, 'txt_record_value') and getattr(self, 'txt_record_value') is not None:
            _dict['txt_record_value'] = getattr(self, 'txt_record_value')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ChallengeResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ChallengeResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ChallengeResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CollectionMetadata():
    """
    The metadata that describes the resource array.

    :attr str collection_type: The type of resources in the resource array.
    :attr int collection_total: The number of elements in the resource array.
    """

    def __init__(self,
                 collection_type: str,
                 collection_total: int) -> None:
        """
        Initialize a CollectionMetadata object.

        :param str collection_type: The type of resources in the resource array.
        :param int collection_total: The number of elements in the resource array.
        """
        self.collection_type = collection_type
        self.collection_total = collection_total

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CollectionMetadata':
        """Initialize a CollectionMetadata object from a json dictionary."""
        args = {}
        if 'collection_type' in _dict:
            args['collection_type'] = _dict.get('collection_type')
        else:
            raise ValueError('Required property \'collection_type\' not present in CollectionMetadata JSON')
        if 'collection_total' in _dict:
            args['collection_total'] = _dict.get('collection_total')
        else:
            raise ValueError('Required property \'collection_total\' not present in CollectionMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CollectionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'collection_type') and self.collection_type is not None:
            _dict['collection_type'] = self.collection_type
        if hasattr(self, 'collection_total') and self.collection_total is not None:
            _dict['collection_total'] = self.collection_total
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CollectionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CollectionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CollectionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class CollectionTypeEnum(str, Enum):
        """
        The type of resources in the resource array.
        """
        APPLICATION_VND_IBM_SECRETS_MANAGER_CONFIG_JSON = 'application/vnd.ibm.secrets-manager.config+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_JSON = 'application/vnd.ibm.secrets-manager.secret+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_VERSION_JSON = 'application/vnd.ibm.secrets-manager.secret.version+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_POLICY_JSON = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_GROUP_JSON = 'application/vnd.ibm.secrets-manager.secret.group+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_LOCK_JSON = 'application/vnd.ibm.secrets-manager.secret.lock+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_ERROR_JSON = 'application/vnd.ibm.secrets-manager.error+json'


class ConfigAction():
    """
    Properties that describe an action on a configuration element.

    """

    def __init__(self) -> None:
        """
        Initialize a ConfigAction object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['SignCsrAction', 'SignIntermediateAction', 'SetSignedAction', 'RevokeAction']))
        raise Exception(msg)

class ConfigElementActionData():
    """
    The configuration to add or update.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    :attr ConfigElementActionResultConfig config:
    """

    def __init__(self,
                 name: str,
                 type: str,
                 config: 'ConfigElementActionResultConfig') -> None:
        """
        Initialize a ConfigElementActionData object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param ConfigElementActionResultConfig config:
        """
        self.name = name
        self.type = type
        self.config = config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementActionData':
        """Initialize a ConfigElementActionData object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in ConfigElementActionData JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in ConfigElementActionData JSON')
        if 'config' in _dict:
            args['config'] = _dict.get('config')
        else:
            raise ValueError('Required property \'config\' not present in ConfigElementActionData JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementActionData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'config') and self.config is not None:
            if isinstance(self.config, dict):
                _dict['config'] = self.config
            else:
                _dict['config'] = self.config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementActionData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementActionData') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementActionData') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class ConfigElementActionResult():
    """
    Properties that describe an action on a configuration element.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[ConfigElementActionData] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['ConfigElementActionData']) -> None:
        """
        Initialize a ConfigElementActionResult object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[ConfigElementActionData] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementActionResult':
        """Initialize a ConfigElementActionResult object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in ConfigElementActionResult JSON')
        if 'resources' in _dict:
            args['resources'] = [ConfigElementActionData.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in ConfigElementActionResult JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ConfigElementActionResultConfig():
    """
    ConfigElementActionResultConfig.

    """

    def __init__(self) -> None:
        """
        Initialize a ConfigElementActionResultConfig object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['SignCsrActionResult', 'SignIntermediateActionResult', 'RotateCrlActionResult',
                       'SetSignedActionResult', 'RevokeActionResult']))
        raise Exception(msg)

class ConfigElementDef():
    """
    The configuration to add or update.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    :attr ConfigElementDefConfig config: The configuration to define for the
          specified secret type.
    """

    def __init__(self,
                 name: str,
                 type: str,
                 config: 'ConfigElementDefConfig') -> None:
        """
        Initialize a ConfigElementDef object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param ConfigElementDefConfig config: The configuration to define for the
               specified secret type.
        """
        self.name = name
        self.type = type
        self.config = config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementDef':
        """Initialize a ConfigElementDef object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in ConfigElementDef JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in ConfigElementDef JSON')
        if 'config' in _dict:
            args['config'] = _dict.get('config')
        else:
            raise ValueError('Required property \'config\' not present in ConfigElementDef JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementDef object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'config') and self.config is not None:
            if isinstance(self.config, dict):
                _dict['config'] = self.config
            else:
                _dict['config'] = self.config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementDef object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementDef') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementDef') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class ConfigElementDefConfig():
    """
    The configuration to define for the specified secret type.

    """

    def __init__(self) -> None:
        """
        Initialize a ConfigElementDefConfig object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['ConfigElementDefConfigLetsEncryptConfig', 'ConfigElementDefConfigCloudInternetServicesConfig',
                       'ConfigElementDefConfigClassicInfrastructureConfig', 'RootCertificateAuthorityConfig',
                       'IntermediateCertificateAuthorityConfig', 'CertificateTemplateConfig']))
        raise Exception(msg)

class ConfigElementMetadata():
    """
    Properties that describe a configuration element.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    """

    def __init__(self,
                 name: str,
                 type: str) -> None:
        """
        Initialize a ConfigElementMetadata object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        """
        self.name = name
        self.type = type

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementMetadata':
        """Initialize a ConfigElementMetadata object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in ConfigElementMetadata JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in ConfigElementMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class CreateSecret():
    """
    Properties that describe a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretResource] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretResource']) -> None:
        """
        Initialize a CreateSecret object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretResource] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateSecret':
        """Initialize a CreateSecret object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in CreateSecret JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in CreateSecret JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateSecret object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateSecret object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateSecret') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateSecret') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class EngineConfig():
    """
    EngineConfig.

    """

    def __init__(self) -> None:
        """
        Initialize a EngineConfig object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['CreateIAMCredentialsSecretEngineRootConfig']))
        raise Exception(msg)

class GetConfig():
    """
    Configuration for the specified secret type.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[GetConfigResourcesItem] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['GetConfigResourcesItem']) -> None:
        """
        Initialize a GetConfig object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetConfigResourcesItem] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetConfig':
        """Initialize a GetConfig object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetConfig JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetConfigElements():
    """
    Properties that describe a list of configurations.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[GetConfigElementsResourcesItem] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['GetConfigElementsResourcesItem']) -> None:
        """
        Initialize a GetConfigElements object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetConfigElementsResourcesItem] resources: A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetConfigElements':
        """Initialize a GetConfigElements object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetConfigElements JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetConfigElements JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfigElements object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetConfigElements object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetConfigElements') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetConfigElements') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetConfigElementsResourcesItem():
    """
    GetConfigElementsResourcesItem.

    """

    def __init__(self) -> None:
        """
        Initialize a GetConfigElementsResourcesItem object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['GetConfigElementsResourcesItemCertificateAuthoritiesConfig',
                       'GetConfigElementsResourcesItemDnsProvidersConfig', 'RootCertificateAuthoritiesConfig',
                       'IntermediateCertificateAuthoritiesConfig', 'CertificateTemplatesConfig']))
        raise Exception(msg)

class GetConfigResourcesItem():
    """
    GetConfigResourcesItem.

    """

    def __init__(self) -> None:
        """
        Initialize a GetConfigResourcesItem object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['PublicCertSecretEngineRootConfig', 'PrivateCertSecretEngineRootConfig',
                       'IAMCredentialsSecretEngineRootConfig']))
        raise Exception(msg)

class GetInstanceLocks():
    """
    Properties that describe the locks that are associated with an instance.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[InstanceSecretsLocks] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['InstanceSecretsLocks']) -> None:
        """
        Initialize a GetInstanceLocks object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[InstanceSecretsLocks] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetInstanceLocks':
        """Initialize a GetInstanceLocks object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetInstanceLocks JSON')
        if 'resources' in _dict:
            args['resources'] = [InstanceSecretsLocks.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in GetInstanceLocks JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetInstanceLocks object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetInstanceLocks object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetInstanceLocks') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetInstanceLocks') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetNotificationsSettings():
    """
    Properties that describe an existing registration with Event Notifications.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[NotificationsSettings] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['NotificationsSettings']) -> None:
        """
        Initialize a GetNotificationsSettings object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[NotificationsSettings] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetNotificationsSettings':
        """Initialize a GetNotificationsSettings object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetNotificationsSettings JSON')
        if 'resources' in _dict:
            args['resources'] = [NotificationsSettings.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in GetNotificationsSettings JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetNotificationsSettings object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetNotificationsSettings object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetNotificationsSettings') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetNotificationsSettings') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSecret():
    """
    Properties that describe a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretResource] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretResource']) -> None:
        """
        Initialize a GetSecret object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretResource] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecret':
        """Initialize a GetSecret object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSecret JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetSecret JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecret object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecret object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecret') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecret') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSecretLocks():
    """
    Properties that describe the lock of a secret or a secret version.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretsLocks] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretsLocks']) -> None:
        """
        Initialize a GetSecretLocks object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretsLocks] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretLocks':
        """Initialize a GetSecretLocks object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSecretLocks JSON')
        if 'resources' in _dict:
            args['resources'] = [SecretsLocks.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in GetSecretLocks JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretLocks object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretLocks object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretLocks') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretLocks') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSecretPolicies():
    """
    GetSecretPolicies.

    """

    def __init__(self) -> None:
        """
        Initialize a GetSecretPolicies object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['GetSecretPolicyRotation']))
        raise Exception(msg)

class GetSecretVersion():
    """
    Properties that describe the version of a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretVersion] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretVersion']) -> None:
        """
        Initialize a GetSecretVersion object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretVersion] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretVersion':
        """Initialize a GetSecretVersion object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSecretVersion JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetSecretVersion JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSecretVersionMetadata():
    """
    Properties that describe the version of a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretVersionMetadata] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretVersionMetadata']) -> None:
        """
        Initialize a GetSecretVersionMetadata object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretVersionMetadata] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretVersionMetadata':
        """Initialize a GetSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSecretVersionMetadata JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetSecretVersionMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSingleConfigElement():
    """
    Properties that describe a configuration.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[ConfigElementDef] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['ConfigElementDef']) -> None:
        """
        Initialize a GetSingleConfigElement object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[ConfigElementDef] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSingleConfigElement':
        """Initialize a GetSingleConfigElement object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSingleConfigElement JSON')
        if 'resources' in _dict:
            args['resources'] = [ConfigElementDef.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in GetSingleConfigElement JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSingleConfigElement object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSingleConfigElement object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSingleConfigElement') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSingleConfigElement') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class InstanceSecretsLocks():
    """
    Properties that describe the locks that are associated with an instance.

    :attr str secret_id: (optional) The unique ID of the secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr str secret_type: (optional) The secret type.
    :attr List[SecretLockVersion] versions: (optional) A collection of locks that
          are attached to a secret version.
    """

    # The set of defined properties for the class
    _properties = frozenset(['secret_id', 'secret_group_id', 'secret_type', 'versions'])

    def __init__(self,
                 *,
                 secret_id: str = None,
                 secret_group_id: str = None,
                 secret_type: str = None,
                 versions: List['SecretLockVersion'] = None,
                 **kwargs) -> None:
        """
        Initialize a InstanceSecretsLocks object.

        :param List[SecretLockVersion] versions: (optional) A collection of locks
               that are attached to a secret version.
        :param **kwargs: (optional) Any additional properties.
        """
        self.secret_id = secret_id
        self.secret_group_id = secret_group_id
        self.secret_type = secret_type
        self.versions = versions
        for _key, _value in kwargs.items():
            setattr(self, _key, _value)

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'InstanceSecretsLocks':
        """Initialize a InstanceSecretsLocks object from a json dictionary."""
        args = {}
        if 'secret_id' in _dict:
            args['secret_id'] = _dict.get('secret_id')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'versions' in _dict:
            args['versions'] = [SecretLockVersion.from_dict(v) for v in _dict.get('versions')]
        args.update({k: v for (k, v) in _dict.items() if k not in cls._properties})
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a InstanceSecretsLocks object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'secret_id') and getattr(self, 'secret_id') is not None:
            _dict['secret_id'] = getattr(self, 'secret_id')
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'versions') and self.versions is not None:
            versions_list = []
            for v in self.versions:
                if isinstance(v, dict):
                    versions_list.append(v)
                else:
                    versions_list.append(v.to_dict())
            _dict['versions'] = versions_list
        for _key in [k for k in vars(self).keys() if k not in InstanceSecretsLocks._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def get_properties(self) -> Dict:
        """Return a dictionary of arbitrary properties from this instance of InstanceSecretsLocks"""
        _dict = {}

        for _key in [k for k in vars(self).keys() if k not in InstanceSecretsLocks._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def set_properties(self, _dict: dict):
        """Set a dictionary of arbitrary properties to this instance of InstanceSecretsLocks"""
        for _key in [k for k in vars(self).keys() if k not in InstanceSecretsLocks._properties]:
            delattr(self, _key)

        for _key, _value in _dict.items():
            if _key not in InstanceSecretsLocks._properties:
                setattr(self, _key, _value)

    def __str__(self) -> str:
        """Return a `str` version of this InstanceSecretsLocks object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'InstanceSecretsLocks') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'InstanceSecretsLocks') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class IntermediateCertificateAuthoritiesConfigItem():
    """
    Intermediate certificate authorities configuration.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    :attr IntermediateCertificateAuthorityConfig config: (optional) Intermediate
          certificate authority configuration.
    """

    def __init__(self,
                 name: str,
                 type: str,
                 *,
                 config: 'IntermediateCertificateAuthorityConfig' = None) -> None:
        """
        Initialize a IntermediateCertificateAuthoritiesConfigItem object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param IntermediateCertificateAuthorityConfig config: (optional)
               Intermediate certificate authority configuration.
        """
        self.name = name
        self.type = type
        self.config = config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IntermediateCertificateAuthoritiesConfigItem':
        """Initialize a IntermediateCertificateAuthoritiesConfigItem object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError(
                'Required property \'name\' not present in IntermediateCertificateAuthoritiesConfigItem JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError(
                'Required property \'type\' not present in IntermediateCertificateAuthoritiesConfigItem JSON')
        if 'config' in _dict:
            args['config'] = IntermediateCertificateAuthorityConfig.from_dict(_dict.get('config'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IntermediateCertificateAuthoritiesConfigItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'config') and self.config is not None:
            if isinstance(self.config, dict):
                _dict['config'] = self.config
            else:
                _dict['config'] = self.config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IntermediateCertificateAuthoritiesConfigItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IntermediateCertificateAuthoritiesConfigItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IntermediateCertificateAuthoritiesConfigItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class IssuanceInfo():
    """
    Issuance information that is associated with your certificate.

    :attr datetime ordered_on: (optional) The date the certificate was ordered. The
          date format follows RFC 3339.
    :attr str error_code: (optional) A code that identifies an issuance error.
          This field, along with `error_message`, is returned when Secrets Manager
          successfully processes your request, but a certificate is unable to be issued by
          the certificate authority.
    :attr str error_message: (optional) A human-readable message that provides
          details about the issuance error.
    :attr bool bundle_certs: (optional) Indicates whether the issued certificate is
          bundled with intermediate certificates.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr bool auto_rotated: (optional) Indicates whether the issued certificate is
          configured with an automatic rotation policy.
    :attr str ca: (optional) The name that was assigned to the certificate authority
          configuration.
    :attr str dns: (optional) The name that was assigned to the DNS provider
          configuration.
    :attr List[ChallengeResource] challenges: (optional) The set of challenges, will
          be returned only when ordering public certificate using manual DNS
          configuration.
    :attr datetime dns_challenge_validation_time: (optional) The date a user called
          "validate dns challenges" for "manual" DNS provider. The date format follows RFC
          3339.
    """

    def __init__(self,
                 *,
                 ordered_on: datetime = None,
                 error_code: str = None,
                 error_message: str = None,
                 bundle_certs: bool = None,
                 state: int = None,
                 state_description: str = None,
                 auto_rotated: bool = None,
                 ca: str = None,
                 dns: str = None,
                 challenges: List['ChallengeResource'] = None,
                 dns_challenge_validation_time: datetime = None) -> None:
        """
        Initialize a IssuanceInfo object.

        """
        self.ordered_on = ordered_on
        self.error_code = error_code
        self.error_message = error_message
        self.bundle_certs = bundle_certs
        self.state = state
        self.state_description = state_description
        self.auto_rotated = auto_rotated
        self.ca = ca
        self.dns = dns
        self.challenges = challenges
        self.dns_challenge_validation_time = dns_challenge_validation_time

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IssuanceInfo':
        """Initialize a IssuanceInfo object from a json dictionary."""
        args = {}
        if 'ordered_on' in _dict:
            args['ordered_on'] = string_to_datetime(_dict.get('ordered_on'))
        if 'error_code' in _dict:
            args['error_code'] = _dict.get('error_code')
        if 'error_message' in _dict:
            args['error_message'] = _dict.get('error_message')
        if 'bundle_certs' in _dict:
            args['bundle_certs'] = _dict.get('bundle_certs')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        if 'ca' in _dict:
            args['ca'] = _dict.get('ca')
        if 'dns' in _dict:
            args['dns'] = _dict.get('dns')
        if 'challenges' in _dict:
            args['challenges'] = [ChallengeResource.from_dict(v) for v in _dict.get('challenges')]
        if 'dns_challenge_validation_time' in _dict:
            args['dns_challenge_validation_time'] = string_to_datetime(_dict.get('dns_challenge_validation_time'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IssuanceInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ordered_on') and getattr(self, 'ordered_on') is not None:
            _dict['ordered_on'] = datetime_to_string(getattr(self, 'ordered_on'))
        if hasattr(self, 'error_code') and getattr(self, 'error_code') is not None:
            _dict['error_code'] = getattr(self, 'error_code')
        if hasattr(self, 'error_message') and getattr(self, 'error_message') is not None:
            _dict['error_message'] = getattr(self, 'error_message')
        if hasattr(self, 'bundle_certs') and getattr(self, 'bundle_certs') is not None:
            _dict['bundle_certs'] = getattr(self, 'bundle_certs')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'auto_rotated') and getattr(self, 'auto_rotated') is not None:
            _dict['auto_rotated'] = getattr(self, 'auto_rotated')
        if hasattr(self, 'ca') and getattr(self, 'ca') is not None:
            _dict['ca'] = getattr(self, 'ca')
        if hasattr(self, 'dns') and getattr(self, 'dns') is not None:
            _dict['dns'] = getattr(self, 'dns')
        if hasattr(self, 'challenges') and getattr(self, 'challenges') is not None:
            challenges_list = []
            for v in getattr(self, 'challenges'):
                if isinstance(v, dict):
                    challenges_list.append(v)
                else:
                    challenges_list.append(v.to_dict())
            _dict['challenges'] = challenges_list
        if hasattr(self, 'dns_challenge_validation_time') and getattr(self,
                                                                      'dns_challenge_validation_time') is not None:
            _dict['dns_challenge_validation_time'] = datetime_to_string(getattr(self, 'dns_challenge_validation_time'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IssuanceInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IssuanceInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IssuanceInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ListSecretLocks():
    """
    Properties that describe the locks of a secret or a secret version.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretLockData] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretLockData']) -> None:
        """
        Initialize a ListSecretLocks object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretLockData] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSecretLocks':
        """Initialize a ListSecretLocks object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in ListSecretLocks JSON')
        if 'resources' in _dict:
            args['resources'] = [SecretLockData.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in ListSecretLocks JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSecretLocks object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSecretLocks object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSecretLocks') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSecretLocks') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ListSecretVersions():
    """
    Properties that describe a list of versions of a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretVersionInfo] resources: (optional) A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 *,
                 resources: List['SecretVersionInfo'] = None) -> None:
        """
        Initialize a ListSecretVersions object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretVersionInfo] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSecretVersions':
        """Initialize a ListSecretVersions object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in ListSecretVersions JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSecretVersions object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSecretVersions object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSecretVersions') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSecretVersions') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ListSecrets():
    """
    Properties that describe a list of secrets.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretResource] resources: (optional) A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 *,
                 resources: List['SecretResource'] = None) -> None:
        """
        Initialize a ListSecrets object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretResource] resources: (optional) A collection of
               resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ListSecrets':
        """Initialize a ListSecrets object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in ListSecrets JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ListSecrets object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ListSecrets object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ListSecrets') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ListSecrets') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class LockSecretBodyLocksItem():
    """
    LockSecretBodyLocksItem.

    :attr str name: A human-readable name to assign to the lock. The lock name must
          be unique per secret version.
          To protect your privacy, do not use personal data, such as your name or
          location, as a name for your secret lock.
    :attr str description: (optional) An extended description of the lock.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret lock.
    :attr dict attributes: (optional) Optional information to associate with a lock,
          such as resources CRNs to be used by automation.
    """

    def __init__(self,
                 name: str,
                 *,
                 description: str = None,
                 attributes: dict = None) -> None:
        """
        Initialize a LockSecretBodyLocksItem object.

        :param str name: A human-readable name to assign to the lock. The lock name
               must be unique per secret version.
               To protect your privacy, do not use personal data, such as your name or
               location, as a name for your secret lock.
        :param str description: (optional) An extended description of the lock.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret lock.
        :param dict attributes: (optional) Optional information to associate with a
               lock, such as resources CRNs to be used by automation.
        """
        self.name = name
        self.description = description
        self.attributes = attributes

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'LockSecretBodyLocksItem':
        """Initialize a LockSecretBodyLocksItem object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in LockSecretBodyLocksItem JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'attributes' in _dict:
            args['attributes'] = _dict.get('attributes')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a LockSecretBodyLocksItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'attributes') and self.attributes is not None:
            _dict['attributes'] = self.attributes
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this LockSecretBodyLocksItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'LockSecretBodyLocksItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'LockSecretBodyLocksItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class NotificationsSettings():
    """
    The Event Notifications details.

    :attr str event_notifications_instance_crn: The Cloud Resource Name (CRN) of the
          connected Event Notifications instance.
    """

    def __init__(self,
                 event_notifications_instance_crn: str) -> None:
        """
        Initialize a NotificationsSettings object.

        :param str event_notifications_instance_crn: The Cloud Resource Name (CRN)
               of the connected Event Notifications instance.
        """
        self.event_notifications_instance_crn = event_notifications_instance_crn

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'NotificationsSettings':
        """Initialize a NotificationsSettings object from a json dictionary."""
        args = {}
        if 'event_notifications_instance_crn' in _dict:
            args['event_notifications_instance_crn'] = _dict.get('event_notifications_instance_crn')
        else:
            raise ValueError(
                'Required property \'event_notifications_instance_crn\' not present in NotificationsSettings JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a NotificationsSettings object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'event_notifications_instance_crn') and self.event_notifications_instance_crn is not None:
            _dict['event_notifications_instance_crn'] = self.event_notifications_instance_crn
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this NotificationsSettings object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'NotificationsSettings') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'NotificationsSettings') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RootCertificateAuthoritiesConfigItem():
    """
    Root certificate authorities configuration.

    :attr str name: The human-readable name to assign to your configuration.
    :attr str type: The type of configuration. Value options differ depending on the
          `config_element` property that you want to define.
    :attr RootCertificateAuthorityConfig config: (optional) Root certificate
          authority configuration.
    """

    def __init__(self,
                 name: str,
                 type: str,
                 *,
                 config: 'RootCertificateAuthorityConfig' = None) -> None:
        """
        Initialize a RootCertificateAuthoritiesConfigItem object.

        :param str name: The human-readable name to assign to your configuration.
        :param str type: The type of configuration. Value options differ depending
               on the `config_element` property that you want to define.
        :param RootCertificateAuthorityConfig config: (optional) Root certificate
               authority configuration.
        """
        self.name = name
        self.type = type
        self.config = config

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RootCertificateAuthoritiesConfigItem':
        """Initialize a RootCertificateAuthoritiesConfigItem object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in RootCertificateAuthoritiesConfigItem JSON')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in RootCertificateAuthoritiesConfigItem JSON')
        if 'config' in _dict:
            args['config'] = RootCertificateAuthorityConfig.from_dict(_dict.get('config'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RootCertificateAuthoritiesConfigItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'config') and self.config is not None:
            if isinstance(self.config, dict):
                _dict['config'] = self.config
            else:
                _dict['config'] = self.config.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RootCertificateAuthoritiesConfigItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RootCertificateAuthoritiesConfigItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RootCertificateAuthoritiesConfigItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The type of configuration. Value options differ depending on the `config_element`
        property that you want to define.
        """
        LETSENCRYPT = 'letsencrypt'
        LETSENCRYPT_STAGE = 'letsencrypt-stage'
        CIS = 'cis'
        CLASSIC_INFRASTRUCTURE = 'classic_infrastructure'
        ROOT_CERTIFICATE_AUTHORITY = 'root_certificate_authority'
        INTERMEDIATE_CERTIFICATE_AUTHORITY = 'intermediate_certificate_authority'
        CERTIFICATE_TEMPLATE = 'certificate_template'


class Rotation():
    """
    Rotation.

    :attr bool auto_rotate: (optional) Determines whether Secrets Manager rotates
          your certificate automatically.
          For public certificates, if `auto_rotate` is set to `true` the service reorders
          your certificate 31 days before it expires. For private certificates, the
          certificate is rotated according to the time interval specified in the
          `interval` and `unit` fields.
          To access the previous version of the certificate, you can use the
          [Get a version of a secret](#get-secret-version) method.
    :attr bool rotate_keys: (optional) Determines whether Secrets Manager rotates
          the private key for your certificate automatically.
          If set to `true`, the service generates and stores a new private key for your
          rotated certificate.
          **Note:** Use this field only for public certificates. It is ignored for private
          certificates.
    :attr int interval: (optional) Used together with the `unit` field to specify
          the rotation interval. The minimum interval is one day, and the maximum interval
          is 3 years (1095 days). Required in case `auto_rotate` is set to `true`.
          **Note:** Use this field only for private certificates. It is ignored for public
          certificates.
    :attr str unit: (optional) The time unit of the rotation interval.
          **Note:** Use this field only for private certificates. It is ignored for public
          certificates.
    """

    def __init__(self,
                 *,
                 auto_rotate: bool = None,
                 rotate_keys: bool = None,
                 interval: int = None,
                 unit: str = None) -> None:
        """
        Initialize a Rotation object.

        :param bool auto_rotate: (optional) Determines whether Secrets Manager
               rotates your certificate automatically.
               For public certificates, if `auto_rotate` is set to `true` the service
               reorders your certificate 31 days before it expires. For private
               certificates, the certificate is rotated according to the time interval
               specified in the `interval` and `unit` fields.
               To access the previous version of the certificate, you can use the
               [Get a version of a secret](#get-secret-version) method.
        :param bool rotate_keys: (optional) Determines whether Secrets Manager
               rotates the private key for your certificate automatically.
               If set to `true`, the service generates and stores a new private key for
               your rotated certificate.
               **Note:** Use this field only for public certificates. It is ignored for
               private certificates.
        :param int interval: (optional) Used together with the `unit` field to
               specify the rotation interval. The minimum interval is one day, and the
               maximum interval is 3 years (1095 days). Required in case `auto_rotate` is
               set to `true`.
               **Note:** Use this field only for private certificates. It is ignored for
               public certificates.
        :param str unit: (optional) The time unit of the rotation interval.
               **Note:** Use this field only for private certificates. It is ignored for
               public certificates.
        """
        self.auto_rotate = auto_rotate
        self.rotate_keys = rotate_keys
        self.interval = interval
        self.unit = unit

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Rotation':
        """Initialize a Rotation object from a json dictionary."""
        args = {}
        if 'auto_rotate' in _dict:
            args['auto_rotate'] = _dict.get('auto_rotate')
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
        if 'interval' in _dict:
            args['interval'] = _dict.get('interval')
        if 'unit' in _dict:
            args['unit'] = _dict.get('unit')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a Rotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_rotate') and self.auto_rotate is not None:
            _dict['auto_rotate'] = self.auto_rotate
        if hasattr(self, 'rotate_keys') and self.rotate_keys is not None:
            _dict['rotate_keys'] = self.rotate_keys
        if hasattr(self, 'interval') and self.interval is not None:
            _dict['interval'] = self.interval
        if hasattr(self, 'unit') and self.unit is not None:
            _dict['unit'] = self.unit
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this Rotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'Rotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'Rotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class UnitEnum(str, Enum):
        """
        The time unit of the rotation interval.
        **Note:** Use this field only for private certificates. It is ignored for public
        certificates.
        """
        DAY = 'day'
        MONTH = 'month'


class SecretAction():
    """
    SecretAction.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretAction object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['RotateArbitrarySecretBody', 'RotatePublicCertBody', 'RotateUsernamePasswordSecretBody',
                       'RotateCertificateBody', 'RotatePrivateCertBody', 'RotatePrivateCertBodyWithCsr',
                       'RotatePrivateCertBodyWithVersionCustomMetadata', 'RestoreIAMCredentialsSecretBody',
                       'DeleteCredentialsForIAMCredentialsSecret', 'RotateKvSecretBody']))
        raise Exception(msg)

class SecretGroupDef():
    """
    Properties that describe a secret group.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretGroupResource] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretGroupResource']) -> None:
        """
        Initialize a SecretGroupDef object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretGroupResource] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretGroupDef':
        """Initialize a SecretGroupDef object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in SecretGroupDef JSON')
        if 'resources' in _dict:
            args['resources'] = [SecretGroupResource.from_dict(v) for v in _dict.get('resources')]
        else:
            raise ValueError('Required property \'resources\' not present in SecretGroupDef JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretGroupDef object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretGroupDef object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretGroupDef') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretGroupDef') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretGroupMetadataUpdatable():
    """
    Metadata properties to update for a secret group.

    :attr str name: (optional) A human-readable name to assign to your secret group.
          To protect your privacy, do not use personal data, such as your name or
          location, as a name for your secret group.
    :attr str description: (optional) An extended description of your secret group.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret group.
    """

    def __init__(self,
                 *,
                 name: str = None,
                 description: str = None) -> None:
        """
        Initialize a SecretGroupMetadataUpdatable object.

        :param str name: (optional) A human-readable name to assign to your secret
               group.
               To protect your privacy, do not use personal data, such as your name or
               location, as a name for your secret group.
        :param str description: (optional) An extended description of your secret
               group.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret group.
        """
        self.name = name
        self.description = description

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretGroupMetadataUpdatable':
        """Initialize a SecretGroupMetadataUpdatable object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretGroupMetadataUpdatable object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretGroupMetadataUpdatable object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretGroupMetadataUpdatable') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretGroupMetadataUpdatable') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretGroupResource():
    """
    Properties that describe a secret group.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret group.
    :attr str name: (optional) A human-readable name to assign to your secret group.
          To protect your privacy, do not use personal data, such as your name or
          location, as a name for your secret group.
    :attr str description: (optional) An extended description of your secret group.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret group.
    :attr datetime creation_date: (optional) The date the secret group was created.
          The date format follows RFC 3339.
    :attr datetime last_update_date: (optional) Updates when the metadata of the
          secret group is modified. The date format follows RFC 3339.
    :attr str type: (optional) The MIME type that represents the secret group.
    """

    # The set of defined properties for the class
    _properties = frozenset(['id', 'name', 'description', 'creation_date', 'last_update_date', 'type'])

    def __init__(self,
                 *,
                 id: str = None,
                 name: str = None,
                 description: str = None,
                 creation_date: datetime = None,
                 last_update_date: datetime = None,
                 type: str = None,
                 **kwargs) -> None:
        """
        Initialize a SecretGroupResource object.

        :param str name: (optional) A human-readable name to assign to your secret
               group.
               To protect your privacy, do not use personal data, such as your name or
               location, as a name for your secret group.
        :param str description: (optional) An extended description of your secret
               group.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret group.
        :param **kwargs: (optional) Any additional properties.
        """
        self.id = id
        self.name = name
        self.description = description
        self.creation_date = creation_date
        self.last_update_date = last_update_date
        self.type = type
        for _key, _value in kwargs.items():
            setattr(self, _key, _value)

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretGroupResource':
        """Initialize a SecretGroupResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        args.update({k: v for (k, v) in _dict.items() if k not in cls._properties})
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretGroupResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'type') and getattr(self, 'type') is not None:
            _dict['type'] = getattr(self, 'type')
        for _key in [k for k in vars(self).keys() if k not in SecretGroupResource._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def get_properties(self) -> Dict:
        """Return a dictionary of arbitrary properties from this instance of SecretGroupResource"""
        _dict = {}

        for _key in [k for k in vars(self).keys() if k not in SecretGroupResource._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def set_properties(self, _dict: dict):
        """Set a dictionary of arbitrary properties to this instance of SecretGroupResource"""
        for _key in [k for k in vars(self).keys() if k not in SecretGroupResource._properties]:
            delattr(self, _key)

        for _key, _value in _dict.items():
            if _key not in SecretGroupResource._properties:
                setattr(self, _key, _value)

    def __str__(self) -> str:
        """Return a `str` version of this SecretGroupResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretGroupResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretGroupResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretLockData():
    """
    Properties that describe a lock.

    :attr str name: (optional) A human-readable name to assign to the secret lock.
          To protect your privacy, do not use personal data, such as your name or
          location, as a name for the secret lock.
    :attr str description: (optional) An extended description of the secret lock.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for the secret lock.
    :attr datetime creation_date: (optional) The date the secret lock was created.
          The date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret lock.
    :attr dict attributes: (optional) The information that is associated with a
          lock, such as resources CRNs to be used by automation.
    :attr str secret_version_id: (optional) The v4 UUID that uniquely identifies the
          secret version.
    :attr str secret_id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr str secret_version_alias: (optional) A representation for the 2 last
          secret versions. Could be "current" for version (n) or "previous" for version
          (n-1).
    """

    def __init__(self,
                 *,
                 name: str = None,
                 description: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 attributes: dict = None,
                 secret_version_id: str = None,
                 secret_id: str = None,
                 secret_group_id: str = None,
                 last_update_date: datetime = None,
                 secret_version_alias: str = None) -> None:
        """
        Initialize a SecretLockData object.

        :param str name: (optional) A human-readable name to assign to the secret
               lock.
               To protect your privacy, do not use personal data, such as your name or
               location, as a name for the secret lock.
        :param str description: (optional) An extended description of the secret
               lock.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for the secret lock.
        :param dict attributes: (optional) The information that is associated with
               a lock, such as resources CRNs to be used by automation.
        """
        self.name = name
        self.description = description
        self.creation_date = creation_date
        self.created_by = created_by
        self.attributes = attributes
        self.secret_version_id = secret_version_id
        self.secret_id = secret_id
        self.secret_group_id = secret_group_id
        self.last_update_date = last_update_date
        self.secret_version_alias = secret_version_alias

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretLockData':
        """Initialize a SecretLockData object from a json dictionary."""
        args = {}
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'attributes' in _dict:
            args['attributes'] = _dict.get('attributes')
        if 'secret_version_id' in _dict:
            args['secret_version_id'] = _dict.get('secret_version_id')
        if 'secret_id' in _dict:
            args['secret_id'] = _dict.get('secret_id')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'secret_version_alias' in _dict:
            args['secret_version_alias'] = _dict.get('secret_version_alias')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretLockData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'attributes') and self.attributes is not None:
            _dict['attributes'] = self.attributes
        if hasattr(self, 'secret_version_id') and getattr(self, 'secret_version_id') is not None:
            _dict['secret_version_id'] = getattr(self, 'secret_version_id')
        if hasattr(self, 'secret_id') and getattr(self, 'secret_id') is not None:
            _dict['secret_id'] = getattr(self, 'secret_id')
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'secret_version_alias') and getattr(self, 'secret_version_alias') is not None:
            _dict['secret_version_alias'] = getattr(self, 'secret_version_alias')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretLockData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretLockData') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretLockData') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretLockVersion():
    """
    Properties that describe the secret locks.

    :attr str id: (optional) The v4 UUID that uniquely identifies the lock.
    :attr str alias: (optional) A human-readable alias that describes the secret
          version. 'Current' is used for version `n` and 'previous' is used for version
          `n-1`.
    :attr List[str] locks: (optional) The names of all locks that are associated
          with this secret.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    """

    # The set of defined properties for the class
    _properties = frozenset(['id', 'alias', 'locks', 'payload_available'])

    def __init__(self,
                 *,
                 id: str = None,
                 alias: str = None,
                 locks: List[str] = None,
                 payload_available: bool = None,
                 **kwargs) -> None:
        """
        Initialize a SecretLockVersion object.

        :param str alias: (optional) A human-readable alias that describes the
               secret version. 'Current' is used for version `n` and 'previous' is used
               for version `n-1`.
        :param List[str] locks: (optional) The names of all locks that are
               associated with this secret.
        :param **kwargs: (optional) Any additional properties.
        """
        self.id = id
        self.alias = alias
        self.locks = locks
        self.payload_available = payload_available
        for _key, _value in kwargs.items():
            setattr(self, _key, _value)

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretLockVersion':
        """Initialize a SecretLockVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'alias' in _dict:
            args['alias'] = _dict.get('alias')
        if 'locks' in _dict:
            args['locks'] = _dict.get('locks')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        args.update({k: v for (k, v) in _dict.items() if k not in cls._properties})
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretLockVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'alias') and self.alias is not None:
            _dict['alias'] = self.alias
        if hasattr(self, 'locks') and self.locks is not None:
            _dict['locks'] = self.locks
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        for _key in [k for k in vars(self).keys() if k not in SecretLockVersion._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def get_properties(self) -> Dict:
        """Return a dictionary of arbitrary properties from this instance of SecretLockVersion"""
        _dict = {}

        for _key in [k for k in vars(self).keys() if k not in SecretLockVersion._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def set_properties(self, _dict: dict):
        """Set a dictionary of arbitrary properties to this instance of SecretLockVersion"""
        for _key in [k for k in vars(self).keys() if k not in SecretLockVersion._properties]:
            delattr(self, _key)

        for _key, _value in _dict.items():
            if _key not in SecretLockVersion._properties:
                setattr(self, _key, _value)

    def __str__(self) -> str:
        """Return a `str` version of this SecretLockVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretLockVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretLockVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class AliasEnum(str, Enum):
        """
        A human-readable alias that describes the secret version. 'Current' is used for
        version `n` and 'previous' is used for version `n-1`.
        """
        CURRENT = 'current'
        PREVIOUS = 'previous'


class SecretMetadata():
    """
    SecretMetadata.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretMetadata object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['ArbitrarySecretMetadata', 'UsernamePasswordSecretMetadata', 'IAMCredentialsSecretMetadata',
                       'CertificateSecretMetadata', 'PublicCertificateSecretMetadata',
                       'PrivateCertificateSecretMetadata', 'KvSecretMetadata']))
        raise Exception(msg)

class SecretMetadataRequest():
    """
    The metadata of a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[SecretMetadata] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['SecretMetadata']) -> None:
        """
        Initialize a SecretMetadataRequest object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretMetadata] resources: A collection of resources.
        """
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretMetadataRequest':
        """Initialize a SecretMetadataRequest object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in SecretMetadataRequest JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in SecretMetadataRequest JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretMetadataRequest object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for v in self.resources:
                if isinstance(v, dict):
                    resources_list.append(v)
                else:
                    resources_list.append(v.to_dict())
            _dict['resources'] = resources_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretMetadataRequest object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretMetadataRequest') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretMetadataRequest') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretPolicyRotation():
    """
    Properties that describe a rotation policy.

    :attr str type: The MIME type that represents the policy. Currently, only the
          default is supported.
    :attr SecretPolicyRotationRotation rotation:
    """

    def __init__(self,
                 type: str,
                 rotation: 'SecretPolicyRotationRotation') -> None:
        """
        Initialize a SecretPolicyRotation object.

        :param str type: The MIME type that represents the policy. Currently, only
               the default is supported.
        :param SecretPolicyRotationRotation rotation:
        """
        self.type = type
        self.rotation = rotation

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretPolicyRotation':
        """Initialize a SecretPolicyRotation object from a json dictionary."""
        args = {}
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError('Required property \'type\' not present in SecretPolicyRotation JSON')
        if 'rotation' in _dict:
            args['rotation'] = _dict.get('rotation')
        else:
            raise ValueError('Required property \'rotation\' not present in SecretPolicyRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'rotation') and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The MIME type that represents the policy. Currently, only the default is
        supported.
        """
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_POLICY_JSON = 'application/vnd.ibm.secrets-manager.secret.policy+json'


class SecretPolicyRotationRotation():
    """
    SecretPolicyRotationRotation.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretPolicyRotationRotation object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                ['SecretPolicyRotationRotationPolicyRotation', 'SecretPolicyRotationRotationPublicCertPolicyRotation',
                 'PrivateCertPolicyRotation']))
        raise Exception(msg)

class SecretResource():
    """
    SecretResource.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretResource object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['ArbitrarySecretResource', 'UsernamePasswordSecretResource', 'IAMCredentialsSecretResource',
                       'CertificateSecretResource', 'PublicCertificateSecretResource',
                       'PrivateCertificateSecretResource', 'KvSecretResource']))
        raise Exception(msg)

class SecretVersion():
    """
    SecretVersion.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretVersion object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['ArbitrarySecretVersion', 'UsernamePasswordSecretVersion', 'IAMCredentialsSecretVersion',
                       'CertificateSecretVersion', 'PrivateCertificateSecretVersion']))
        raise Exception(msg)

class SecretVersionInfo():
    """
    Properties that describe a secret version within a list of secret versions.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretVersionInfo object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                ['ArbitrarySecretVersionInfo', 'UsernamePasswordSecretVersionInfo', 'IAMCredentialsSecretVersionInfo',
                 'CertificateSecretVersionInfo', 'PrivateCertificateSecretVersionInfo']))
        raise Exception(msg)

class SecretVersionMetadata():
    """
    SecretVersionMetadata.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretVersionMetadata object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['ArbitrarySecretVersionMetadata', 'UsernamePasswordSecretVersionMetadata',
                       'IAMCredentialsSecretVersionMetadata', 'CertificateSecretVersionMetadata',
                       'PrivateCertificateSecretVersionMetadata']))
        raise Exception(msg)

class SecretsLocks():
    """
    Properties that describe the secret locks.

    :attr str secret_id: (optional) The unique ID of the secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[SecretLockVersion] versions: (optional) A collection of locks that
          are attached to a secret version.
    """

    # The set of defined properties for the class
    _properties = frozenset(['secret_id', 'secret_group_id', 'versions'])

    def __init__(self,
                 *,
                 secret_id: str = None,
                 secret_group_id: str = None,
                 versions: List['SecretLockVersion'] = None,
                 **kwargs) -> None:
        """
        Initialize a SecretsLocks object.

        :param List[SecretLockVersion] versions: (optional) A collection of locks
               that are attached to a secret version.
        :param **kwargs: (optional) Any additional properties.
        """
        self.secret_id = secret_id
        self.secret_group_id = secret_group_id
        self.versions = versions
        for _key, _value in kwargs.items():
            setattr(self, _key, _value)

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretsLocks':
        """Initialize a SecretsLocks object from a json dictionary."""
        args = {}
        if 'secret_id' in _dict:
            args['secret_id'] = _dict.get('secret_id')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'versions' in _dict:
            args['versions'] = [SecretLockVersion.from_dict(v) for v in _dict.get('versions')]
        args.update({k: v for (k, v) in _dict.items() if k not in cls._properties})
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretsLocks object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'secret_id') and getattr(self, 'secret_id') is not None:
            _dict['secret_id'] = getattr(self, 'secret_id')
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'versions') and self.versions is not None:
            versions_list = []
            for v in self.versions:
                if isinstance(v, dict):
                    versions_list.append(v)
                else:
                    versions_list.append(v.to_dict())
            _dict['versions'] = versions_list
        for _key in [k for k in vars(self).keys() if k not in SecretsLocks._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def get_properties(self) -> Dict:
        """Return a dictionary of arbitrary properties from this instance of SecretsLocks"""
        _dict = {}

        for _key in [k for k in vars(self).keys() if k not in SecretsLocks._properties]:
            _dict[_key] = getattr(self, _key)
        return _dict

    def set_properties(self, _dict: dict):
        """Set a dictionary of arbitrary properties to this instance of SecretsLocks"""
        for _key in [k for k in vars(self).keys() if k not in SecretsLocks._properties]:
            delattr(self, _key)

        for _key, _value in _dict.items():
            if _key not in SecretsLocks._properties:
                setattr(self, _key, _value)

    def __str__(self) -> str:
        """Return a `str` version of this SecretsLocks object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretsLocks') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretsLocks') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SignActionResultData():
    """
    Properties that are returned with a successful `sign` action.

    :attr str certificate: (optional) The PEM-encoded certificate.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str issuing_ca: (optional) The PEM-encoded certificate of the certificate
          authority that signed and issued this certificate.
    :attr List[str] ca_chain: (optional) The chain of certificate authorities that
          are associated with the certificate.
    :attr int expiration: (optional) The time until the certificate expires.
    """

    def __init__(self,
                 *,
                 certificate: str = None,
                 serial_number: str = None,
                 issuing_ca: str = None,
                 ca_chain: List[str] = None,
                 expiration: int = None) -> None:
        """
        Initialize a SignActionResultData object.

        :param str certificate: (optional) The PEM-encoded certificate.
        :param str issuing_ca: (optional) The PEM-encoded certificate of the
               certificate authority that signed and issued this certificate.
        :param List[str] ca_chain: (optional) The chain of certificate authorities
               that are associated with the certificate.
        :param int expiration: (optional) The time until the certificate expires.
        """
        self.certificate = certificate
        self.serial_number = serial_number
        self.issuing_ca = issuing_ca
        self.ca_chain = ca_chain
        self.expiration = expiration

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignActionResultData':
        """Initialize a SignActionResultData object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'issuing_ca' in _dict:
            args['issuing_ca'] = _dict.get('issuing_ca')
        if 'ca_chain' in _dict:
            args['ca_chain'] = _dict.get('ca_chain')
        if 'expiration' in _dict:
            args['expiration'] = _dict.get('expiration')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignActionResultData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'issuing_ca') and self.issuing_ca is not None:
            _dict['issuing_ca'] = self.issuing_ca
        if hasattr(self, 'ca_chain') and self.ca_chain is not None:
            _dict['ca_chain'] = self.ca_chain
        if hasattr(self, 'expiration') and self.expiration is not None:
            _dict['expiration'] = self.expiration
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignActionResultData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignActionResultData') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignActionResultData') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SignIntermediateActionResultData():
    """
    Properties that are returned with a successful `sign` action.

    :attr str certificate: (optional) The PEM-encoded certificate.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str issuing_ca: (optional) The PEM-encoded certificate of the certificate
          authority that signed and issued this certificate.
    :attr List[str] ca_chain: (optional) The chain of certificate authorities that
          are associated with the certificate.
    :attr int expiration: (optional) The time until the certificate expires.
    """

    def __init__(self,
                 *,
                 certificate: str = None,
                 serial_number: str = None,
                 issuing_ca: str = None,
                 ca_chain: List[str] = None,
                 expiration: int = None) -> None:
        """
        Initialize a SignIntermediateActionResultData object.

        :param str certificate: (optional) The PEM-encoded certificate.
        :param str issuing_ca: (optional) The PEM-encoded certificate of the
               certificate authority that signed and issued this certificate.
        :param List[str] ca_chain: (optional) The chain of certificate authorities
               that are associated with the certificate.
        :param int expiration: (optional) The time until the certificate expires.
        """
        self.certificate = certificate
        self.serial_number = serial_number
        self.issuing_ca = issuing_ca
        self.ca_chain = ca_chain
        self.expiration = expiration

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignIntermediateActionResultData':
        """Initialize a SignIntermediateActionResultData object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'issuing_ca' in _dict:
            args['issuing_ca'] = _dict.get('issuing_ca')
        if 'ca_chain' in _dict:
            args['ca_chain'] = _dict.get('ca_chain')
        if 'expiration' in _dict:
            args['expiration'] = _dict.get('expiration')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignIntermediateActionResultData object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'issuing_ca') and self.issuing_ca is not None:
            _dict['issuing_ca'] = self.issuing_ca
        if hasattr(self, 'ca_chain') and self.ca_chain is not None:
            _dict['ca_chain'] = self.ca_chain
        if hasattr(self, 'expiration') and self.expiration is not None:
            _dict['expiration'] = self.expiration
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignIntermediateActionResultData object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignIntermediateActionResultData') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignIntermediateActionResultData') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class UpdateSecretVersionMetadata():
    """
    Properties that update the metadata of a secret version.

    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 *,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a UpdateSecretVersionMetadata object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UpdateSecretVersionMetadata':
        """Initialize a UpdateSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UpdateSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UpdateSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UpdateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UpdateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CertificateValidity():
    """
    CertificateValidity.

    :attr datetime not_before: (optional) The date and time that the certificate
          validity period begins.
    :attr datetime not_after: (optional) The date and time that the certificate
          validity period ends.
    """

    def __init__(self,
                 *,
                 not_before: datetime = None,
                 not_after: datetime = None) -> None:
        """
        Initialize a CertificateValidity object.

        :param datetime not_before: (optional) The date and time that the
               certificate validity period begins.
        :param datetime not_after: (optional) The date and time that the
               certificate validity period ends.
        """
        self.not_before = not_before
        self.not_after = not_after

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateValidity':
        """Initialize a CertificateValidity object from a json dictionary."""
        args = {}
        if 'not_before' in _dict:
            args['not_before'] = string_to_datetime(_dict.get('not_before'))
        if 'not_after' in _dict:
            args['not_after'] = string_to_datetime(_dict.get('not_after'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateValidity object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'not_before') and self.not_before is not None:
            _dict['not_before'] = datetime_to_string(self.not_before)
        if hasattr(self, 'not_after') and self.not_after is not None:
            _dict['not_after'] = datetime_to_string(self.not_after)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateValidity object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateValidity') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateValidity') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ArbitrarySecretMetadata(SecretMetadata):
    """
    Metadata properties that describe an arbitrary secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 expiration_date: datetime = None) -> None:
        """
        Initialize a ArbitrarySecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.expiration_date = expiration_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretMetadata':
        """Initialize a ArbitrarySecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in ArbitrarySecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ArbitrarySecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ArbitrarySecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ArbitrarySecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class ArbitrarySecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr str payload: (optional) The new secret data to assign to the secret.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version.
          The data object contains the field `payload`.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 expiration_date: datetime = None,
                 payload: str = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a ArbitrarySecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        :param str payload: (optional) The new secret data to assign to the secret.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.expiration_date = expiration_date
        self.payload = payload
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretResource':
        """Initialize a ArbitrarySecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in ArbitrarySecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        if hasattr(self, 'payload') and self.payload is not None:
            _dict['payload'] = self.payload
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ArbitrarySecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ArbitrarySecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ArbitrarySecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class ArbitrarySecretVersion(SecretVersion):
    """
    ArbitrarySecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version.
          The data object contains the field `payload`.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a ArbitrarySecretVersion object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param dict secret_data: (optional) The data that is associated with the
               secret version.
               The data object contains the field `payload`.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretVersion':
        """Initialize a ArbitrarySecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'secret_data') and self.secret_data is not None:
            _dict['secret_data'] = self.secret_data
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ArbitrarySecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ArbitrarySecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ArbitrarySecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ArbitrarySecretVersionInfo(SecretVersionInfo):
    """
    ArbitrarySecretVersionInfo.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a ArbitrarySecretVersionInfo object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretVersionInfo':
        """Initialize a ArbitrarySecretVersionInfo object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretVersionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ArbitrarySecretVersionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ArbitrarySecretVersionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ArbitrarySecretVersionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ArbitrarySecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a ArbitrarySecretVersionMetadata object.

        :param str id: (optional) The v4 UUID that uniquely identifies the secret.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretVersionMetadata':
        """Initialize a ArbitrarySecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ArbitrarySecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ArbitrarySecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ArbitrarySecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CertificateSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a certificate secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          that was used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public and private keys that are
          associated with the certificate.
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr CertificateValidity validity: (optional)
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name that is defined for the certificate.
    :attr bool intermediate_included: (optional) Indicates whether the certificate
          was imported with an associated intermediate certificate.
    :attr bool private_key_included: (optional) Indicates whether the certificate
          was imported with an associated private key.
    :attr List[str] alt_names: (optional) The alternative names that are defined for
          the certificate.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 serial_number: str = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 issuer: str = None,
                 validity: 'CertificateValidity' = None,
                 common_name: str = None,
                 intermediate_included: bool = None,
                 private_key_included: bool = None,
                 alt_names: List[str] = None,
                 expiration_date: datetime = None) -> None:
        """
        Initialize a CertificateSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.serial_number = serial_number
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.issuer = issuer
        self.validity = validity
        self.common_name = common_name
        self.intermediate_included = intermediate_included
        self.private_key_included = private_key_included
        self.alt_names = alt_names
        self.expiration_date = expiration_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretMetadata':
        """Initialize a CertificateSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in CertificateSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'intermediate_included' in _dict:
            args['intermediate_included'] = _dict.get('intermediate_included')
        if 'private_key_included' in _dict:
            args['private_key_included'] = _dict.get('private_key_included')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and getattr(self, 'key_algorithm') is not None:
            _dict['key_algorithm'] = getattr(self, 'key_algorithm')
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'common_name') and getattr(self, 'common_name') is not None:
            _dict['common_name'] = getattr(self, 'common_name')
        if hasattr(self, 'intermediate_included') and getattr(self, 'intermediate_included') is not None:
            _dict['intermediate_included'] = getattr(self, 'intermediate_included')
        if hasattr(self, 'private_key_included') and getattr(self, 'private_key_included') is not None:
            _dict['private_key_included'] = getattr(self, 'private_key_included')
        if hasattr(self, 'alt_names') and getattr(self, 'alt_names') is not None:
            _dict['alt_names'] = getattr(self, 'alt_names')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class CertificateSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str certificate: (optional) The contents of your certificate. The data
          must be formatted on a single line with embedded newline characters.
    :attr str private_key: (optional) The private key to associate with the
          certificate. The data must be formatted on a single line with embedded newline
          characters.
    :attr str intermediate: (optional) The intermediate certificate to associate
          with the root certificate. The data must be formatted on a single line with
          embedded newline characters.
    :attr dict secret_data: (optional) The data that is associated with the secret.
          The data object contains the following fields:
          - `certificate`: The contents of the certificate.
          - `private_key`: The private key that is associated with the certificate.
          - `intermediate`: The intermediate certificate that is associated with the
          certificate.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          that was used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public and private keys that are
          associated with the certificate.
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr CertificateValidity validity: (optional)
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name that is defined for the certificate.
    :attr bool intermediate_included: (optional) Indicates whether the certificate
          was imported with an associated intermediate certificate.
    :attr bool private_key_included: (optional) Indicates whether the certificate
          was imported with an associated private key.
    :attr object alt_names: (optional) The alternative names that are defined for
          the certificate.
          For public certificates, this value is provided as an array of strings. For
          private certificates, this value is provided as a comma-delimited list (string).
          In the API response, this value is returned as an array of strings for all the
          types of certificate secrets.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 certificate: str = None,
                 private_key: str = None,
                 intermediate: str = None,
                 secret_data: dict = None,
                 serial_number: str = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 issuer: str = None,
                 validity: 'CertificateValidity' = None,
                 common_name: str = None,
                 intermediate_included: bool = None,
                 private_key_included: bool = None,
                 alt_names: object = None,
                 expiration_date: datetime = None) -> None:
        """
        Initialize a CertificateSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param str certificate: (optional) The contents of your certificate. The
               data must be formatted on a single line with embedded newline characters.
        :param str private_key: (optional) The private key to associate with the
               certificate. The data must be formatted on a single line with embedded
               newline characters.
        :param str intermediate: (optional) The intermediate certificate to
               associate with the root certificate. The data must be formatted on a single
               line with embedded newline characters.
        :param object alt_names: (optional) The alternative names that are defined
               for the certificate.
               For public certificates, this value is provided as an array of strings. For
               private certificates, this value is provided as a comma-delimited list
               (string). In the API response, this value is returned as an array of
               strings for all the types of certificate secrets.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.certificate = certificate
        self.private_key = private_key
        self.intermediate = intermediate
        self.secret_data = secret_data
        self.serial_number = serial_number
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.issuer = issuer
        self.validity = validity
        self.common_name = common_name
        self.intermediate_included = intermediate_included
        self.private_key_included = private_key_included
        self.alt_names = alt_names
        self.expiration_date = expiration_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretResource':
        """Initialize a CertificateSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in CertificateSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        if 'private_key' in _dict:
            args['private_key'] = _dict.get('private_key')
        if 'intermediate' in _dict:
            args['intermediate'] = _dict.get('intermediate')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'intermediate_included' in _dict:
            args['intermediate_included'] = _dict.get('intermediate_included')
        if 'private_key_included' in _dict:
            args['private_key_included'] = _dict.get('private_key_included')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'private_key') and self.private_key is not None:
            _dict['private_key'] = self.private_key
        if hasattr(self, 'intermediate') and self.intermediate is not None:
            _dict['intermediate'] = self.intermediate
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and getattr(self, 'key_algorithm') is not None:
            _dict['key_algorithm'] = getattr(self, 'key_algorithm')
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'common_name') and getattr(self, 'common_name') is not None:
            _dict['common_name'] = getattr(self, 'common_name')
        if hasattr(self, 'intermediate_included') and getattr(self, 'intermediate_included') is not None:
            _dict['intermediate_included'] = getattr(self, 'intermediate_included')
        if hasattr(self, 'private_key_included') and getattr(self, 'private_key_included') is not None:
            _dict['private_key_included'] = getattr(self, 'private_key_included')
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class CertificateSecretVersion(SecretVersion):
    """
    CertificateSecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateSecretData secret_data: (optional) The data that is associated
          with the secret version. The data object contains the following fields:
          - `certificate`: The contents of the certificate.
          - `private_key`: The private key that is associated with the certificate.
          - `intermediate`: The intermediate certificate that is associated with the
          certificate.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 secret_data: 'CertificateSecretData' = None) -> None:
        """
        Initialize a CertificateSecretVersion object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.validity = validity
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretVersion':
        """Initialize a CertificateSecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'secret_data' in _dict:
            args['secret_data'] = CertificateSecretData.from_dict(_dict.get('secret_data'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            if isinstance(getattr(self, 'secret_data'), dict):
                _dict['secret_data'] = getattr(self, 'secret_data')
            else:
                _dict['secret_data'] = getattr(self, 'secret_data').to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CertificateSecretVersionInfo(SecretVersionInfo):
    """
    CertificateSecretVersionInfo.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateValidity validity: (optional)
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 version_custom_metadata: dict = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 validity: 'CertificateValidity' = None) -> None:
        """
        Initialize a CertificateSecretVersionInfo object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.version_custom_metadata = version_custom_metadata
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.validity = validity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretVersionInfo':
        """Initialize a CertificateSecretVersionInfo object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretVersionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretVersionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretVersionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretVersionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CertificateSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateValidity validity: (optional)
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 validity: 'CertificateValidity' = None) -> None:
        """
        Initialize a CertificateSecretVersionMetadata object.

        :param str id: (optional) The v4 UUID that uniquely identifies the secret.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.validity = validity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretVersionMetadata':
        """Initialize a CertificateSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CertificateTemplateConfig(ConfigElementDefConfig):
    """
    Properties that describe a certificate template. You can use a certificate template to
    control the parameters that  are applied to your issued private certificates. For more
    information, see the
    [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-certificate-templates).

    :attr str certificate_authority: The name of the intermediate certificate
          authority.
    :attr str allowed_secret_groups: (optional) Scopes the creation of private
          certificates to only the secret groups that you specify.
          This field can be supplied as a comma-delimited list of secret group IDs.
    :attr object max_ttl: (optional) The maximum time-to-live (TTL) for certificates
          that are created by this CA.
          The value can be supplied as a string representation of a duration in hours, for
          example '8760h'. In the API response, this value is returned in seconds
          (integer).
          Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration, such as
          `12h`. The value can be supplied in seconds (suffix `s`), minutes (suffix `m`)
          or hours (suffix `h`). The value can't exceed the `max_ttl` that is defined in
          the associated certificate template. In the API response, this value is returned
          in seconds (integer).
    :attr bool allow_localhost: (optional) Determines whether to allow `localhost`
          to be included as one of the requested common names.
    :attr List[str] allowed_domains: (optional) The domains to define for the
          certificate template. This property is used along with the `allow_bare_domains`
          and `allow_subdomains` options.
    :attr bool allowed_domains_template: (optional) Determines whether to allow the
          domains that are supplied in the `allowed_domains` field to contain access
          control list (ACL) templates.
    :attr bool allow_bare_domains: (optional) Determines whether to allow clients to
          request private certificates that match the value of the actual domains on the
          final certificate.
          For example, if you specify `example.com` in the `allowed_domains` field, you
          grant clients the ability to request a certificate that contains the name
          `example.com` as one of the DNS values on the final certificate.
          **Important:** In some scenarios, allowing bare domains can be considered a
          security risk.
    :attr bool allow_subdomains: (optional) Determines whether to allow clients to
          request private certificates with common names (CN) that are subdomains of the
          CNs that are allowed by the other certificate template options. This includes
          wildcard subdomains.
          For example, if `allowed_domains` has a value of `example.com` and
          `allow_subdomains`is set to `true`, then the following subdomains are allowed:
          `foo.example.com`, `bar.example.com`, `*.example.com`.
          **Note:** This field is redundant if you use the `allow_any_name` option.
    :attr bool allow_glob_domains: (optional) Determines whether to allow glob
          patterns, for example, `ftp*.example.com`, in the names that are specified in
          the `allowed_domains` field.
          If set to `true`, clients are allowed to request private certificates with names
          that match the glob patterns.
    :attr bool allow_any_name: (optional) Determines whether to allow clients to
          request a private certificate that matches any common name.
    :attr bool enforce_hostnames: (optional) Determines whether to enforce only
          valid host names for common names, DNS Subject Alternative Names, and the host
          section of email addresses.
    :attr bool allow_ip_sans: (optional) Determines whether to allow clients to
          request a private certificate with IP Subject Alternative Names.
    :attr List[str] allowed_uri_sans: (optional) The URI Subject Alternative Names
          to allow for private certificates.
          Values can contain glob patterns, for example `spiffe://hostname/*`.
    :attr List[str] allowed_other_sans: (optional) The custom Object Identifier
          (OID) or UTF8-string Subject Alternative Names (SANs) to allow for private
          certificates.
          The format for each element in the list is the same as OpenSSL:
          `<oid>:<type>:<value>` where the current valid type is `UTF8`. To allow any
          value for an OID, use `*` as its value. Alternatively, specify a single `*` to
          allow any `other_sans` input.
    :attr bool server_flag: (optional) Determines whether private certificates are
          flagged for server use.
    :attr bool client_flag: (optional) Determines whether private certificates are
          flagged for client use.
    :attr bool code_signing_flag: (optional) Determines whether private certificates
          are flagged for code signing use.
    :attr bool email_protection_flag: (optional) Determines whether private
          certificates are flagged for email protection use.
    :attr str key_type: (optional) The type of private key to generate for private
          certificates and the type of key that is expected for submitted certificate
          signing requests (CSRs).
          Allowable values are: `rsa` and `ec`.
    :attr int key_bits: (optional) The number of bits to use when generating the
          private key.
          Allowable values for RSA keys are: `2048` and `4096`. Allowable values for EC
          keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is `2048`.
          The default for EC keys is `256`.
    :attr List[str] key_usage: (optional) The allowed key usage constraint to define
          for private certificates.
          You can find valid values in the [Go x509 package
          documentation](https://pkg.go.dev/crypto/x509#KeyUsage).  Omit the `KeyUsage`
          part of the value. Values are not case-sensitive. To specify no key usage
          constraints, set this field to an empty list.
    :attr List[str] ext_key_usage: (optional) The allowed extended key usage
          constraint on private certificates.
          You can find valid values in the [Go x509 package
          documentation](https://golang.org/pkg/crypto/x509/#ExtKeyUsage). Omit the
          `ExtKeyUsage` part of the value. Values are not case-sensitive. To specify no
          key usage constraints, set this field to an empty list.
    :attr List[str] ext_key_usage_oids: (optional) A list of extended key usage
          Object Identifiers (OIDs).
    :attr bool use_csr_common_name: (optional) When used with the `sign_csr` action,
          this field determines whether to use the common name (CN) from a certificate
          signing request (CSR) instead of the CN that's included in the JSON data of the
          certificate.
          Does not include any requested Subject Alternative Names (SANs) in the CSR. To
          use the alternative names, include the `use_csr_sans` property.
    :attr bool use_csr_sans: (optional) When used with the `sign_csr` action, this
          field determines whether to use the Subject Alternative Names
          (SANs) from a certificate signing request (CSR) instead of the SANs that are
          included in the JSON data of the certificate.
          Does not include the common name in the CSR. To use the common name, include the
          `use_csr_common_name` property.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr bool require_cn: (optional) Determines whether to require a common name to
          create a private certificate.
          By default, a common name is required to generate a certificate. To make the
          `common_name` field optional, set the `require_cn` option to `false`.
    :attr List[str] policy_identifiers: (optional) A list of policy Object
          Identifiers (OIDs).
    :attr bool basic_constraints_valid_for_non_ca: (optional) Determines whether to
          mark the Basic Constraints extension of an issued private certificate as valid
          for non-CA certificates.
    :attr object not_before_duration: (optional) The duration in seconds by which to
          backdate the `not_before` property of an issued private certificate.
          The value can be supplied as a string representation of a duration, such as
          `30s`. In the API response, this value is returned in seconds (integer).
    """

    def __init__(self,
                 certificate_authority: str,
                 *,
                 allowed_secret_groups: str = None,
                 max_ttl: object = None,
                 ttl: object = None,
                 allow_localhost: bool = None,
                 allowed_domains: List[str] = None,
                 allowed_domains_template: bool = None,
                 allow_bare_domains: bool = None,
                 allow_subdomains: bool = None,
                 allow_glob_domains: bool = None,
                 allow_any_name: bool = None,
                 enforce_hostnames: bool = None,
                 allow_ip_sans: bool = None,
                 allowed_uri_sans: List[str] = None,
                 allowed_other_sans: List[str] = None,
                 server_flag: bool = None,
                 client_flag: bool = None,
                 code_signing_flag: bool = None,
                 email_protection_flag: bool = None,
                 key_type: str = None,
                 key_bits: int = None,
                 key_usage: List[str] = None,
                 ext_key_usage: List[str] = None,
                 ext_key_usage_oids: List[str] = None,
                 use_csr_common_name: bool = None,
                 use_csr_sans: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None,
                 require_cn: bool = None,
                 policy_identifiers: List[str] = None,
                 basic_constraints_valid_for_non_ca: bool = None,
                 not_before_duration: object = None) -> None:
        """
        Initialize a CertificateTemplateConfig object.

        :param str certificate_authority: The name of the intermediate certificate
               authority.
        :param str allowed_secret_groups: (optional) Scopes the creation of private
               certificates to only the secret groups that you specify.
               This field can be supplied as a comma-delimited list of secret group IDs.
        :param object max_ttl: (optional) The maximum time-to-live (TTL) for
               certificates that are created by this CA.
               The value can be supplied as a string representation of a duration in
               hours, for example '8760h'. In the API response, this value is returned in
               seconds (integer).
               Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration, such as
               `12h`. The value can be supplied in seconds (suffix `s`), minutes (suffix
               `m`) or hours (suffix `h`). The value can't exceed the `max_ttl` that is
               defined in the associated certificate template. In the API response, this
               value is returned in seconds (integer).
        :param bool allow_localhost: (optional) Determines whether to allow
               `localhost` to be included as one of the requested common names.
        :param List[str] allowed_domains: (optional) The domains to define for the
               certificate template. This property is used along with the
               `allow_bare_domains` and `allow_subdomains` options.
        :param bool allowed_domains_template: (optional) Determines whether to
               allow the domains that are supplied in the `allowed_domains` field to
               contain access control list (ACL) templates.
        :param bool allow_bare_domains: (optional) Determines whether to allow
               clients to request private certificates that match the value of the actual
               domains on the final certificate.
               For example, if you specify `example.com` in the `allowed_domains` field,
               you grant clients the ability to request a certificate that contains the
               name `example.com` as one of the DNS values on the final certificate.
               **Important:** In some scenarios, allowing bare domains can be considered a
               security risk.
        :param bool allow_subdomains: (optional) Determines whether to allow
               clients to request private certificates with common names (CN) that are
               subdomains of the CNs that are allowed by the other certificate template
               options. This includes wildcard subdomains.
               For example, if `allowed_domains` has a value of `example.com` and
               `allow_subdomains`is set to `true`, then the following subdomains are
               allowed: `foo.example.com`, `bar.example.com`, `*.example.com`.
               **Note:** This field is redundant if you use the `allow_any_name` option.
        :param bool allow_glob_domains: (optional) Determines whether to allow glob
               patterns, for example, `ftp*.example.com`, in the names that are specified
               in the `allowed_domains` field.
               If set to `true`, clients are allowed to request private certificates with
               names that match the glob patterns.
        :param bool allow_any_name: (optional) Determines whether to allow clients
               to request a private certificate that matches any common name.
        :param bool enforce_hostnames: (optional) Determines whether to enforce
               only valid host names for common names, DNS Subject Alternative Names, and
               the host section of email addresses.
        :param bool allow_ip_sans: (optional) Determines whether to allow clients
               to request a private certificate with IP Subject Alternative Names.
        :param List[str] allowed_uri_sans: (optional) The URI Subject Alternative
               Names to allow for private certificates.
               Values can contain glob patterns, for example `spiffe://hostname/*`.
        :param List[str] allowed_other_sans: (optional) The custom Object
               Identifier (OID) or UTF8-string Subject Alternative Names (SANs) to allow
               for private certificates.
               The format for each element in the list is the same as OpenSSL:
               `<oid>:<type>:<value>` where the current valid type is `UTF8`. To allow any
               value for an OID, use `*` as its value. Alternatively, specify a single `*`
               to allow any `other_sans` input.
        :param bool server_flag: (optional) Determines whether private certificates
               are flagged for server use.
        :param bool client_flag: (optional) Determines whether private certificates
               are flagged for client use.
        :param bool code_signing_flag: (optional) Determines whether private
               certificates are flagged for code signing use.
        :param bool email_protection_flag: (optional) Determines whether private
               certificates are flagged for email protection use.
        :param str key_type: (optional) The type of private key to generate for
               private certificates and the type of key that is expected for submitted
               certificate signing requests (CSRs).
               Allowable values are: `rsa` and `ec`.
        :param int key_bits: (optional) The number of bits to use when generating
               the private key.
               Allowable values for RSA keys are: `2048` and `4096`. Allowable values for
               EC keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is
               `2048`. The default for EC keys is `256`.
        :param List[str] key_usage: (optional) The allowed key usage constraint to
               define for private certificates.
               You can find valid values in the [Go x509 package
               documentation](https://pkg.go.dev/crypto/x509#KeyUsage).  Omit the
               `KeyUsage` part of the value. Values are not case-sensitive. To specify no
               key usage constraints, set this field to an empty list.
        :param List[str] ext_key_usage: (optional) The allowed extended key usage
               constraint on private certificates.
               You can find valid values in the [Go x509 package
               documentation](https://golang.org/pkg/crypto/x509/#ExtKeyUsage). Omit the
               `ExtKeyUsage` part of the value. Values are not case-sensitive. To specify
               no key usage constraints, set this field to an empty list.
        :param List[str] ext_key_usage_oids: (optional) A list of extended key
               usage Object Identifiers (OIDs).
        :param bool use_csr_common_name: (optional) When used with the `sign_csr`
               action, this field determines whether to use the common name (CN) from a
               certificate signing request (CSR) instead of the CN that's included in the
               JSON data of the certificate.
               Does not include any requested Subject Alternative Names (SANs) in the CSR.
               To use the alternative names, include the `use_csr_sans` property.
        :param bool use_csr_sans: (optional) When used with the `sign_csr` action,
               this field determines whether to use the Subject Alternative Names
               (SANs) from a certificate signing request (CSR) instead of the SANs that
               are included in the JSON data of the certificate.
               Does not include the common name in the CSR. To use the common name,
               include the `use_csr_common_name` property.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        :param bool require_cn: (optional) Determines whether to require a common
               name to create a private certificate.
               By default, a common name is required to generate a certificate. To make
               the `common_name` field optional, set the `require_cn` option to `false`.
        :param List[str] policy_identifiers: (optional) A list of policy Object
               Identifiers (OIDs).
        :param bool basic_constraints_valid_for_non_ca: (optional) Determines
               whether to mark the Basic Constraints extension of an issued private
               certificate as valid for non-CA certificates.
        :param object not_before_duration: (optional) The duration in seconds by
               which to backdate the `not_before` property of an issued private
               certificate.
               The value can be supplied as a string representation of a duration, such as
               `30s`. In the API response, this value is returned in seconds (integer).
        """
        # pylint: disable=super-init-not-called
        self.certificate_authority = certificate_authority
        self.allowed_secret_groups = allowed_secret_groups
        self.max_ttl = max_ttl
        self.ttl = ttl
        self.allow_localhost = allow_localhost
        self.allowed_domains = allowed_domains
        self.allowed_domains_template = allowed_domains_template
        self.allow_bare_domains = allow_bare_domains
        self.allow_subdomains = allow_subdomains
        self.allow_glob_domains = allow_glob_domains
        self.allow_any_name = allow_any_name
        self.enforce_hostnames = enforce_hostnames
        self.allow_ip_sans = allow_ip_sans
        self.allowed_uri_sans = allowed_uri_sans
        self.allowed_other_sans = allowed_other_sans
        self.server_flag = server_flag
        self.client_flag = client_flag
        self.code_signing_flag = code_signing_flag
        self.email_protection_flag = email_protection_flag
        self.key_type = key_type
        self.key_bits = key_bits
        self.key_usage = key_usage
        self.ext_key_usage = ext_key_usage
        self.ext_key_usage_oids = ext_key_usage_oids
        self.use_csr_common_name = use_csr_common_name
        self.use_csr_sans = use_csr_sans
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.require_cn = require_cn
        self.policy_identifiers = policy_identifiers
        self.basic_constraints_valid_for_non_ca = basic_constraints_valid_for_non_ca
        self.not_before_duration = not_before_duration

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateTemplateConfig':
        """Initialize a CertificateTemplateConfig object from a json dictionary."""
        args = {}
        if 'certificate_authority' in _dict:
            args['certificate_authority'] = _dict.get('certificate_authority')
        else:
            raise ValueError(
                'Required property \'certificate_authority\' not present in CertificateTemplateConfig JSON')
        if 'allowed_secret_groups' in _dict:
            args['allowed_secret_groups'] = _dict.get('allowed_secret_groups')
        if 'max_ttl' in _dict:
            args['max_ttl'] = _dict.get('max_ttl')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'allow_localhost' in _dict:
            args['allow_localhost'] = _dict.get('allow_localhost')
        if 'allowed_domains' in _dict:
            args['allowed_domains'] = _dict.get('allowed_domains')
        if 'allowed_domains_template' in _dict:
            args['allowed_domains_template'] = _dict.get('allowed_domains_template')
        if 'allow_bare_domains' in _dict:
            args['allow_bare_domains'] = _dict.get('allow_bare_domains')
        if 'allow_subdomains' in _dict:
            args['allow_subdomains'] = _dict.get('allow_subdomains')
        if 'allow_glob_domains' in _dict:
            args['allow_glob_domains'] = _dict.get('allow_glob_domains')
        if 'allow_any_name' in _dict:
            args['allow_any_name'] = _dict.get('allow_any_name')
        if 'enforce_hostnames' in _dict:
            args['enforce_hostnames'] = _dict.get('enforce_hostnames')
        if 'allow_ip_sans' in _dict:
            args['allow_ip_sans'] = _dict.get('allow_ip_sans')
        if 'allowed_uri_sans' in _dict:
            args['allowed_uri_sans'] = _dict.get('allowed_uri_sans')
        if 'allowed_other_sans' in _dict:
            args['allowed_other_sans'] = _dict.get('allowed_other_sans')
        if 'server_flag' in _dict:
            args['server_flag'] = _dict.get('server_flag')
        if 'client_flag' in _dict:
            args['client_flag'] = _dict.get('client_flag')
        if 'code_signing_flag' in _dict:
            args['code_signing_flag'] = _dict.get('code_signing_flag')
        if 'email_protection_flag' in _dict:
            args['email_protection_flag'] = _dict.get('email_protection_flag')
        if 'key_type' in _dict:
            args['key_type'] = _dict.get('key_type')
        if 'key_bits' in _dict:
            args['key_bits'] = _dict.get('key_bits')
        if 'key_usage' in _dict:
            args['key_usage'] = _dict.get('key_usage')
        if 'ext_key_usage' in _dict:
            args['ext_key_usage'] = _dict.get('ext_key_usage')
        if 'ext_key_usage_oids' in _dict:
            args['ext_key_usage_oids'] = _dict.get('ext_key_usage_oids')
        if 'use_csr_common_name' in _dict:
            args['use_csr_common_name'] = _dict.get('use_csr_common_name')
        if 'use_csr_sans' in _dict:
            args['use_csr_sans'] = _dict.get('use_csr_sans')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'require_cn' in _dict:
            args['require_cn'] = _dict.get('require_cn')
        if 'policy_identifiers' in _dict:
            args['policy_identifiers'] = _dict.get('policy_identifiers')
        if 'basic_constraints_valid_for_non_ca' in _dict:
            args['basic_constraints_valid_for_non_ca'] = _dict.get('basic_constraints_valid_for_non_ca')
        if 'not_before_duration' in _dict:
            args['not_before_duration'] = _dict.get('not_before_duration')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateTemplateConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_authority') and self.certificate_authority is not None:
            _dict['certificate_authority'] = self.certificate_authority
        if hasattr(self, 'allowed_secret_groups') and self.allowed_secret_groups is not None:
            _dict['allowed_secret_groups'] = self.allowed_secret_groups
        if hasattr(self, 'max_ttl') and self.max_ttl is not None:
            _dict['max_ttl'] = self.max_ttl
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'allow_localhost') and self.allow_localhost is not None:
            _dict['allow_localhost'] = self.allow_localhost
        if hasattr(self, 'allowed_domains') and self.allowed_domains is not None:
            _dict['allowed_domains'] = self.allowed_domains
        if hasattr(self, 'allowed_domains_template') and self.allowed_domains_template is not None:
            _dict['allowed_domains_template'] = self.allowed_domains_template
        if hasattr(self, 'allow_bare_domains') and self.allow_bare_domains is not None:
            _dict['allow_bare_domains'] = self.allow_bare_domains
        if hasattr(self, 'allow_subdomains') and self.allow_subdomains is not None:
            _dict['allow_subdomains'] = self.allow_subdomains
        if hasattr(self, 'allow_glob_domains') and self.allow_glob_domains is not None:
            _dict['allow_glob_domains'] = self.allow_glob_domains
        if hasattr(self, 'allow_any_name') and self.allow_any_name is not None:
            _dict['allow_any_name'] = self.allow_any_name
        if hasattr(self, 'enforce_hostnames') and self.enforce_hostnames is not None:
            _dict['enforce_hostnames'] = self.enforce_hostnames
        if hasattr(self, 'allow_ip_sans') and self.allow_ip_sans is not None:
            _dict['allow_ip_sans'] = self.allow_ip_sans
        if hasattr(self, 'allowed_uri_sans') and self.allowed_uri_sans is not None:
            _dict['allowed_uri_sans'] = self.allowed_uri_sans
        if hasattr(self, 'allowed_other_sans') and self.allowed_other_sans is not None:
            _dict['allowed_other_sans'] = self.allowed_other_sans
        if hasattr(self, 'server_flag') and self.server_flag is not None:
            _dict['server_flag'] = self.server_flag
        if hasattr(self, 'client_flag') and self.client_flag is not None:
            _dict['client_flag'] = self.client_flag
        if hasattr(self, 'code_signing_flag') and self.code_signing_flag is not None:
            _dict['code_signing_flag'] = self.code_signing_flag
        if hasattr(self, 'email_protection_flag') and self.email_protection_flag is not None:
            _dict['email_protection_flag'] = self.email_protection_flag
        if hasattr(self, 'key_type') and self.key_type is not None:
            _dict['key_type'] = self.key_type
        if hasattr(self, 'key_bits') and self.key_bits is not None:
            _dict['key_bits'] = self.key_bits
        if hasattr(self, 'key_usage') and self.key_usage is not None:
            _dict['key_usage'] = self.key_usage
        if hasattr(self, 'ext_key_usage') and self.ext_key_usage is not None:
            _dict['ext_key_usage'] = self.ext_key_usage
        if hasattr(self, 'ext_key_usage_oids') and self.ext_key_usage_oids is not None:
            _dict['ext_key_usage_oids'] = self.ext_key_usage_oids
        if hasattr(self, 'use_csr_common_name') and self.use_csr_common_name is not None:
            _dict['use_csr_common_name'] = self.use_csr_common_name
        if hasattr(self, 'use_csr_sans') and self.use_csr_sans is not None:
            _dict['use_csr_sans'] = self.use_csr_sans
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'require_cn') and self.require_cn is not None:
            _dict['require_cn'] = self.require_cn
        if hasattr(self, 'policy_identifiers') and self.policy_identifiers is not None:
            _dict['policy_identifiers'] = self.policy_identifiers
        if hasattr(self, 'basic_constraints_valid_for_non_ca') and self.basic_constraints_valid_for_non_ca is not None:
            _dict['basic_constraints_valid_for_non_ca'] = self.basic_constraints_valid_for_non_ca
        if hasattr(self, 'not_before_duration') and self.not_before_duration is not None:
            _dict['not_before_duration'] = self.not_before_duration
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateTemplateConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateTemplateConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateTemplateConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class KeyTypeEnum(str, Enum):
        """
        The type of private key to generate for private certificates and the type of key
        that is expected for submitted certificate signing requests (CSRs).
        Allowable values are: `rsa` and `ec`.
        """
        RSA = 'rsa'
        EC = 'ec'


class CertificateTemplatesConfig(GetConfigElementsResourcesItem):
    """
    Certificate templates configuration.

    :attr List[CertificateTemplatesConfigItem] certificate_templates:
    """

    def __init__(self,
                 certificate_templates: List['CertificateTemplatesConfigItem']) -> None:
        """
        Initialize a CertificateTemplatesConfig object.

        :param List[CertificateTemplatesConfigItem] certificate_templates:
        """
        # pylint: disable=super-init-not-called
        self.certificate_templates = certificate_templates

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateTemplatesConfig':
        """Initialize a CertificateTemplatesConfig object from a json dictionary."""
        args = {}
        if 'certificate_templates' in _dict:
            args['certificate_templates'] = [CertificateTemplatesConfigItem.from_dict(v) for v in
                                             _dict.get('certificate_templates')]
        else:
            raise ValueError(
                'Required property \'certificate_templates\' not present in CertificateTemplatesConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateTemplatesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_templates') and self.certificate_templates is not None:
            certificate_templates_list = []
            for v in self.certificate_templates:
                if isinstance(v, dict):
                    certificate_templates_list.append(v)
                else:
                    certificate_templates_list.append(v.to_dict())
            _dict['certificate_templates'] = certificate_templates_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CertificateTemplatesConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CertificateTemplatesConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CertificateTemplatesConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ConfigElementDefConfigClassicInfrastructureConfig(ConfigElementDefConfig):
    """
    Properties that describe an IBM Cloud classic infrastructure (SoftLayer)
    configuration.

    :attr str classic_infrastructure_username: The username that is associated with
          your classic infrastructure account.
          In most cases, your classic infrastructure username is your
          `<account_id>_<email_address>`. For more information, see the
          [docs](https://cloud.ibm.com/docs/account?topic=account-classic_keys).
    :attr str classic_infrastructure_password: Your classic infrastructure API key.
          For information about viewing and accessing your classic infrastructure API key,
          see the [docs](https://cloud.ibm.com/docs/account?topic=account-classic_keys).
    """

    def __init__(self,
                 classic_infrastructure_username: str,
                 classic_infrastructure_password: str) -> None:
        """
        Initialize a ConfigElementDefConfigClassicInfrastructureConfig object.

        :param str classic_infrastructure_username: The username that is associated
               with your classic infrastructure account.
               In most cases, your classic infrastructure username is your
               `<account_id>_<email_address>`. For more information, see the
               [docs](https://cloud.ibm.com/docs/account?topic=account-classic_keys).
        :param str classic_infrastructure_password: Your classic infrastructure API
               key.
               For information about viewing and accessing your classic infrastructure API
               key, see the
               [docs](https://cloud.ibm.com/docs/account?topic=account-classic_keys).
        """
        # pylint: disable=super-init-not-called
        self.classic_infrastructure_username = classic_infrastructure_username
        self.classic_infrastructure_password = classic_infrastructure_password

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementDefConfigClassicInfrastructureConfig':
        """Initialize a ConfigElementDefConfigClassicInfrastructureConfig object from a json dictionary."""
        args = {}
        if 'classic_infrastructure_username' in _dict:
            args['classic_infrastructure_username'] = _dict.get('classic_infrastructure_username')
        else:
            raise ValueError(
                'Required property \'classic_infrastructure_username\' not present in ConfigElementDefConfigClassicInfrastructureConfig JSON')
        if 'classic_infrastructure_password' in _dict:
            args['classic_infrastructure_password'] = _dict.get('classic_infrastructure_password')
        else:
            raise ValueError(
                'Required property \'classic_infrastructure_password\' not present in ConfigElementDefConfigClassicInfrastructureConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementDefConfigClassicInfrastructureConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'classic_infrastructure_username') and self.classic_infrastructure_username is not None:
            _dict['classic_infrastructure_username'] = self.classic_infrastructure_username
        if hasattr(self, 'classic_infrastructure_password') and self.classic_infrastructure_password is not None:
            _dict['classic_infrastructure_password'] = self.classic_infrastructure_password
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementDefConfigClassicInfrastructureConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementDefConfigClassicInfrastructureConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementDefConfigClassicInfrastructureConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ConfigElementDefConfigCloudInternetServicesConfig(ConfigElementDefConfig):
    """
    Properties that describe an IBM Cloud Internet Services (CIS) configuration.

    :attr str cis_crn: The Cloud Resource Name (CRN) that is associated with the CIS
          instance.
    :attr str cis_apikey: (optional) An IBM Cloud API key that can to list domains
          in your CIS instance.
          To grant Secrets Manager the ability to view the CIS instance and all of its
          domains, the API key must be assigned the Reader service role on Internet
          Services (`internet-svcs`).
          If you need to manage specific domains, you can assign the Manager role. For
          production environments, it is recommended that you assign the Reader access
          role, and then use the
          [IAM Policy Management
          API](https://cloud.ibm.com/apidocs/iam-policy-management#create-policy) to
          control specific domains. For more information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-prepare-order-certificates#authorize-specific-domains).
    """

    def __init__(self,
                 cis_crn: str,
                 *,
                 cis_apikey: str = None) -> None:
        """
        Initialize a ConfigElementDefConfigCloudInternetServicesConfig object.

        :param str cis_crn: The Cloud Resource Name (CRN) that is associated with
               the CIS instance.
        :param str cis_apikey: (optional) An IBM Cloud API key that can to list
               domains in your CIS instance.
               To grant Secrets Manager the ability to view the CIS instance and all of
               its domains, the API key must be assigned the Reader service role on
               Internet Services (`internet-svcs`).
               If you need to manage specific domains, you can assign the Manager role.
               For production environments, it is recommended that you assign the Reader
               access role, and then use the
               [IAM Policy Management
               API](https://cloud.ibm.com/apidocs/iam-policy-management#create-policy) to
               control specific domains. For more information, see the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-prepare-order-certificates#authorize-specific-domains).
        """
        # pylint: disable=super-init-not-called
        self.cis_crn = cis_crn
        self.cis_apikey = cis_apikey

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementDefConfigCloudInternetServicesConfig':
        """Initialize a ConfigElementDefConfigCloudInternetServicesConfig object from a json dictionary."""
        args = {}
        if 'cis_crn' in _dict:
            args['cis_crn'] = _dict.get('cis_crn')
        else:
            raise ValueError(
                'Required property \'cis_crn\' not present in ConfigElementDefConfigCloudInternetServicesConfig JSON')
        if 'cis_apikey' in _dict:
            args['cis_apikey'] = _dict.get('cis_apikey')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementDefConfigCloudInternetServicesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'cis_crn') and self.cis_crn is not None:
            _dict['cis_crn'] = self.cis_crn
        if hasattr(self, 'cis_apikey') and self.cis_apikey is not None:
            _dict['cis_apikey'] = self.cis_apikey
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementDefConfigCloudInternetServicesConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementDefConfigCloudInternetServicesConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementDefConfigCloudInternetServicesConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class ConfigElementDefConfigLetsEncryptConfig(ConfigElementDefConfig):
    """
    Properties that describe a Let's Encrypt configuration.

    :attr str private_key: The private key that is associated with your Automatic
          Certificate Management Environment (ACME) account.
          If you have a working ACME client or account for Let's Encrypt, you can use the
          existing private key to enable communications with Secrets Manager. If you don't
          have an account yet, you can create one. For more information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-prepare-order-certificates#create-acme-account).
    """

    def __init__(self,
                 private_key: str) -> None:
        """
        Initialize a ConfigElementDefConfigLetsEncryptConfig object.

        :param str private_key: The private key that is associated with your
               Automatic Certificate Management Environment (ACME) account.
               If you have a working ACME client or account for Let's Encrypt, you can use
               the existing private key to enable communications with Secrets Manager. If
               you don't have an account yet, you can create one. For more information,
               see the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-prepare-order-certificates#create-acme-account).
        """
        # pylint: disable=super-init-not-called
        self.private_key = private_key

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ConfigElementDefConfigLetsEncryptConfig':
        """Initialize a ConfigElementDefConfigLetsEncryptConfig object from a json dictionary."""
        args = {}
        if 'private_key' in _dict:
            args['private_key'] = _dict.get('private_key')
        else:
            raise ValueError(
                'Required property \'private_key\' not present in ConfigElementDefConfigLetsEncryptConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ConfigElementDefConfigLetsEncryptConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'private_key') and self.private_key is not None:
            _dict['private_key'] = self.private_key
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this ConfigElementDefConfigLetsEncryptConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'ConfigElementDefConfigLetsEncryptConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'ConfigElementDefConfigLetsEncryptConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class CreateIAMCredentialsSecretEngineRootConfig(EngineConfig):
    """
    Configuration for the IAM credentials engine.

    :attr str api_key: An IBM Cloud API key that can create and manage service IDs.
          The API key must be assigned the Editor platform role on the Access Groups
          Service and the Operator platform role on the IAM Identity Service. For more
          information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-configure-iam-engine).
    :attr str api_key_hash: (optional) The hash value of the IBM Cloud API key that
          is used to create and manage service IDs.
    """

    def __init__(self,
                 api_key: str,
                 *,
                 api_key_hash: str = None) -> None:
        """
        Initialize a CreateIAMCredentialsSecretEngineRootConfig object.

        :param str api_key: An IBM Cloud API key that can create and manage service
               IDs.
               The API key must be assigned the Editor platform role on the Access Groups
               Service and the Operator platform role on the IAM Identity Service. For
               more information, see the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-configure-iam-engine).
        """
        # pylint: disable=super-init-not-called
        self.api_key = api_key
        self.api_key_hash = api_key_hash

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CreateIAMCredentialsSecretEngineRootConfig':
        """Initialize a CreateIAMCredentialsSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        else:
            raise ValueError(
                'Required property \'api_key\' not present in CreateIAMCredentialsSecretEngineRootConfig JSON')
        if 'api_key_hash' in _dict:
            args['api_key_hash'] = _dict.get('api_key_hash')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateIAMCredentialsSecretEngineRootConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key') and self.api_key is not None:
            _dict['api_key'] = self.api_key
        if hasattr(self, 'api_key_hash') and getattr(self, 'api_key_hash') is not None:
            _dict['api_key_hash'] = getattr(self, 'api_key_hash')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this CreateIAMCredentialsSecretEngineRootConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'CreateIAMCredentialsSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'CreateIAMCredentialsSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class DeleteCredentialsForIAMCredentialsSecret(SecretAction):
    """
    Delete the credentials that are associated with an `iam_credentials` secret.

    :attr str api_key_id: (optional) The ID of the API key that you want to delete.
          If the secret was created with a static service ID, only the API key is deleted.
          Otherwise, the service ID is deleted together with its API key.
    :attr str service_id: (optional) Deprecated: The service ID that you want to
          delete. This property can be used instead of the `api_key_id` field, but only
          for secrets that were created with a service ID that was generated by Secrets
          Manager.
          **Deprecated.** Use the `api_key_id` field instead.
    """

    def __init__(self,
                 *,
                 api_key_id: str = None,
                 service_id: str = None) -> None:
        """
        Initialize a DeleteCredentialsForIAMCredentialsSecret object.

        :param str api_key_id: (optional) The ID of the API key that you want to
               delete. If the secret was created with a static service ID, only the API
               key is deleted. Otherwise, the service ID is deleted together with its API
               key.
        :param str service_id: (optional) Deprecated: The service ID that you want
               to delete. This property can be used instead of the `api_key_id` field, but
               only for secrets that were created with a service ID that was generated by
               Secrets Manager.
               **Deprecated.** Use the `api_key_id` field instead.
        """
        # pylint: disable=super-init-not-called
        self.api_key_id = api_key_id
        self.service_id = service_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DeleteCredentialsForIAMCredentialsSecret':
        """Initialize a DeleteCredentialsForIAMCredentialsSecret object from a json dictionary."""
        args = {}
        if 'api_key_id' in _dict:
            args['api_key_id'] = _dict.get('api_key_id')
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeleteCredentialsForIAMCredentialsSecret object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key_id') and self.api_key_id is not None:
            _dict['api_key_id'] = self.api_key_id
        if hasattr(self, 'service_id') and self.service_id is not None:
            _dict['service_id'] = self.service_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this DeleteCredentialsForIAMCredentialsSecret object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'DeleteCredentialsForIAMCredentialsSecret') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'DeleteCredentialsForIAMCredentialsSecret') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetConfigElementsResourcesItemCertificateAuthoritiesConfig(GetConfigElementsResourcesItem):
    """
    Certificate authorities configuration.

    :attr List[ConfigElementMetadata] certificate_authorities:
    """

    def __init__(self,
                 certificate_authorities: List['ConfigElementMetadata']) -> None:
        """
        Initialize a GetConfigElementsResourcesItemCertificateAuthoritiesConfig object.

        :param List[ConfigElementMetadata] certificate_authorities:
        """
        # pylint: disable=super-init-not-called
        self.certificate_authorities = certificate_authorities

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetConfigElementsResourcesItemCertificateAuthoritiesConfig':
        """Initialize a GetConfigElementsResourcesItemCertificateAuthoritiesConfig object from a json dictionary."""
        args = {}
        if 'certificate_authorities' in _dict:
            args['certificate_authorities'] = [ConfigElementMetadata.from_dict(v) for v in
                                               _dict.get('certificate_authorities')]
        else:
            raise ValueError(
                'Required property \'certificate_authorities\' not present in GetConfigElementsResourcesItemCertificateAuthoritiesConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfigElementsResourcesItemCertificateAuthoritiesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_authorities') and self.certificate_authorities is not None:
            certificate_authorities_list = []
            for v in self.certificate_authorities:
                if isinstance(v, dict):
                    certificate_authorities_list.append(v)
                else:
                    certificate_authorities_list.append(v.to_dict())
            _dict['certificate_authorities'] = certificate_authorities_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetConfigElementsResourcesItemCertificateAuthoritiesConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetConfigElementsResourcesItemCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetConfigElementsResourcesItemCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetConfigElementsResourcesItemDnsProvidersConfig(GetConfigElementsResourcesItem):
    """
    DNS providers configuration.

    :attr List[ConfigElementMetadata] dns_providers:
    """

    def __init__(self,
                 dns_providers: List['ConfigElementMetadata']) -> None:
        """
        Initialize a GetConfigElementsResourcesItemDnsProvidersConfig object.

        :param List[ConfigElementMetadata] dns_providers:
        """
        # pylint: disable=super-init-not-called
        self.dns_providers = dns_providers

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetConfigElementsResourcesItemDnsProvidersConfig':
        """Initialize a GetConfigElementsResourcesItemDnsProvidersConfig object from a json dictionary."""
        args = {}
        if 'dns_providers' in _dict:
            args['dns_providers'] = [ConfigElementMetadata.from_dict(v) for v in _dict.get('dns_providers')]
        else:
            raise ValueError(
                'Required property \'dns_providers\' not present in GetConfigElementsResourcesItemDnsProvidersConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfigElementsResourcesItemDnsProvidersConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'dns_providers') and self.dns_providers is not None:
            dns_providers_list = []
            for v in self.dns_providers:
                if isinstance(v, dict):
                    dns_providers_list.append(v)
                else:
                    dns_providers_list.append(v.to_dict())
            _dict['dns_providers'] = dns_providers_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetConfigElementsResourcesItemDnsProvidersConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetConfigElementsResourcesItemDnsProvidersConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetConfigElementsResourcesItemDnsProvidersConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class GetSecretPolicyRotation(GetSecretPolicies):
    """
    Properties that describe a rotation policy.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[dict] resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List[dict]) -> None:
        """
        Initialize a GetSecretPolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[dict] resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretPolicyRotation':
        """Initialize a GetSecretPolicyRotation object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError('Required property \'metadata\' not present in GetSecretPolicyRotation JSON')
        if 'resources' in _dict:
            args['resources'] = _dict.get('resources')
        else:
            raise ValueError('Required property \'resources\' not present in GetSecretPolicyRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            if isinstance(self.metadata, dict):
                _dict['metadata'] = self.metadata
            else:
                _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = self.resources
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IAMCredentialsSecretEngineRootConfig(GetConfigResourcesItem):
    """
    Configuration for the IAM credentials engine.

    :attr str api_key: An IBM Cloud API key that can create and manage service IDs.
          The API key must be assigned the Editor platform role on the Access Groups
          Service and the Operator platform role on the IAM Identity Service. For more
          information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-configure-iam-engine).
    :attr str api_key_hash: (optional) The hash value of the IBM Cloud API key that
          is used to create and manage service IDs.
    """

    def __init__(self,
                 api_key: str,
                 *,
                 api_key_hash: str = None) -> None:
        """
        Initialize a IAMCredentialsSecretEngineRootConfig object.

        :param str api_key: An IBM Cloud API key that can create and manage service
               IDs.
               The API key must be assigned the Editor platform role on the Access Groups
               Service and the Operator platform role on the IAM Identity Service. For
               more information, see the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-configure-iam-engine).
        """
        # pylint: disable=super-init-not-called
        self.api_key = api_key
        self.api_key_hash = api_key_hash

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretEngineRootConfig':
        """Initialize a IAMCredentialsSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        else:
            raise ValueError('Required property \'api_key\' not present in IAMCredentialsSecretEngineRootConfig JSON')
        if 'api_key_hash' in _dict:
            args['api_key_hash'] = _dict.get('api_key_hash')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretEngineRootConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'api_key') and self.api_key is not None:
            _dict['api_key'] = self.api_key
        if hasattr(self, 'api_key_hash') and getattr(self, 'api_key_hash') is not None:
            _dict['api_key_hash'] = getattr(self, 'api_key_hash')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretEngineRootConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IAMCredentialsSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe an `iam_credentials` secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr str ttl: (optional) The time-to-live (TTL) or lease duration that is
          assigned to the secret. For `iam_credentials` secrets, the TTL defines for how
          long each generated API key remains valid.
    :attr bool reuse_api_key: (optional) Determines whether to use the same service
          ID and API key for future read operations on an
          `iam_credentials` secret.
          If set to `true`, the service reuses the current credentials. If set to `false`,
          a new service ID and API key are generated each time that the secret is read or
          accessed.
    :attr bool service_id_is_static: (optional) Indicates whether an
          `iam_credentials` secret was created with a static service ID.
          If the value is `true`, the service ID for the secret was provided by the user
          at secret creation. If the value is `false`, the service ID was generated by
          Secrets Manager.
    :attr str service_id: (optional) The service ID under which the API key is
          created. The service ID is included in the metadata only if the secret was
          created with a static service ID.
    :attr List[str] access_groups: (optional) The access groups that define the
          capabilities of the service ID and API key that are generated for an
          `iam_credentials` secret. The access groups are included in the metadata only if
          the secret was created with a service ID that was generated by Secrets Manager.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 ttl: str = None,
                 reuse_api_key: bool = None,
                 service_id_is_static: bool = None,
                 service_id: str = None,
                 access_groups: List[str] = None) -> None:
        """
        Initialize a IAMCredentialsSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param str ttl: (optional) The time-to-live (TTL) or lease duration that is
               assigned to the secret. For `iam_credentials` secrets, the TTL defines for
               how long each generated API key remains valid.
        :param bool service_id_is_static: (optional) Indicates whether an
               `iam_credentials` secret was created with a static service ID.
               If the value is `true`, the service ID for the secret was provided by the
               user at secret creation. If the value is `false`, the service ID was
               generated by Secrets Manager.
        :param str service_id: (optional) The service ID under which the API key is
               created. The service ID is included in the metadata only if the secret was
               created with a static service ID.
        :param List[str] access_groups: (optional) The access groups that define
               the capabilities of the service ID and API key that are generated for an
               `iam_credentials` secret. The access groups are included in the metadata
               only if the secret was created with a service ID that was generated by
               Secrets Manager.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.ttl = ttl
        self.reuse_api_key = reuse_api_key
        self.service_id_is_static = service_id_is_static
        self.service_id = service_id
        self.access_groups = access_groups

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretMetadata':
        """Initialize a IAMCredentialsSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in IAMCredentialsSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'reuse_api_key' in _dict:
            args['reuse_api_key'] = _dict.get('reuse_api_key')
        if 'service_id_is_static' in _dict:
            args['service_id_is_static'] = _dict.get('service_id_is_static')
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        if 'access_groups' in _dict:
            args['access_groups'] = _dict.get('access_groups')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'reuse_api_key') and getattr(self, 'reuse_api_key') is not None:
            _dict['reuse_api_key'] = getattr(self, 'reuse_api_key')
        if hasattr(self, 'service_id_is_static') and self.service_id_is_static is not None:
            _dict['service_id_is_static'] = self.service_id_is_static
        if hasattr(self, 'service_id') and self.service_id is not None:
            _dict['service_id'] = self.service_id
        if hasattr(self, 'access_groups') and self.access_groups is not None:
            _dict['access_groups'] = self.access_groups
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class IAMCredentialsSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr object ttl: (optional) The time-to-live (TTL) or lease duration to assign
          to generated credentials.
          For `iam_credentials` secrets, the TTL defines for how long each generated API
          key remains valid. The value can be either an integer that specifies the number
          of seconds, or the string representation of a duration, such as `120m` or `24h`.
          Minimum duration is 1 minute. Maximum is 90 days.
    :attr List[str] access_groups: (optional) The access groups that define the
          capabilities of the service ID and API key that are generated for an
          `iam_credentials` secret. If you prefer to use an existing service ID that is
          already assigned the access policies that you require, you can omit this
          parameter and use the `service_id` field instead.
          **Tip:** To list the access groups that are available in an account, you can use
          the [IAM Access Groups
          API](https://cloud.ibm.com/apidocs/iam-access-groups#list-access-groups). To
          find the ID of an access group in the console, go to **Manage > Access (IAM) >
          Access groups**. Select the access group to inspect, and click **Details** to
          view its ID.
    :attr str api_key: (optional) The API key that is generated for this secret.
          After the secret reaches the end of its lease (see the `ttl` field), the API key
          is deleted automatically. If you want to continue to use the same API key for
          future read operations, see the `reuse_api_key` field.
    :attr str api_key_id: (optional) The ID of the API key that is generated for
          this secret.
    :attr str service_id: (optional) The service ID under which the API key (see the
          `api_key` field) is created.
          If you omit this parameter, Secrets Manager generates a new service ID for your
          secret at its creation and adds it to the access groups that you assign.
          Optionally, you can use this field to provide your own service ID if you prefer
          to manage its access directly or retain the service ID after your secret
          expires, is rotated, or deleted. If you provide a service ID, do not include the
          `access_groups` parameter.
    :attr bool service_id_is_static: (optional) Indicates whether an
          `iam_credentials` secret was created with a static service ID.
          If `true`, the service ID for the secret was provided by the user at secret
          creation. If `false`, the service ID was generated by Secrets Manager.
    :attr bool reuse_api_key: (optional) Determines whether to use the same service
          ID and API key for future read operations on an
          `iam_credentials` secret.
          If set to `true`, the service reuses the current credentials. If set to `false`,
          a new service ID and API key are generated each time that the secret is read or
          accessed.
    :attr datetime next_rotation_date: (optional) The date that the secret is
          scheduled for automatic rotation.
          The service automatically creates a new version of the secret on its next
          rotation date. This field exists only for secrets that have an existing rotation
          policy.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 ttl: object = None,
                 access_groups: List[str] = None,
                 api_key: str = None,
                 api_key_id: str = None,
                 service_id: str = None,
                 service_id_is_static: bool = None,
                 reuse_api_key: bool = None,
                 next_rotation_date: datetime = None) -> None:
        """
        Initialize a IAMCredentialsSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param object ttl: (optional) The time-to-live (TTL) or lease duration to
               assign to generated credentials.
               For `iam_credentials` secrets, the TTL defines for how long each generated
               API key remains valid. The value can be either an integer that specifies
               the number of seconds, or the string representation of a duration, such as
               `120m` or `24h`.
               Minimum duration is 1 minute. Maximum is 90 days.
        :param List[str] access_groups: (optional) The access groups that define
               the capabilities of the service ID and API key that are generated for an
               `iam_credentials` secret. If you prefer to use an existing service ID that
               is already assigned the access policies that you require, you can omit this
               parameter and use the `service_id` field instead.
               **Tip:** To list the access groups that are available in an account, you
               can use the [IAM Access Groups
               API](https://cloud.ibm.com/apidocs/iam-access-groups#list-access-groups).
               To find the ID of an access group in the console, go to **Manage > Access
               (IAM) > Access groups**. Select the access group to inspect, and click
               **Details** to view its ID.
        :param str service_id: (optional) The service ID under which the API key
               (see the `api_key` field) is created.
               If you omit this parameter, Secrets Manager generates a new service ID for
               your secret at its creation and adds it to the access groups that you
               assign.
               Optionally, you can use this field to provide your own service ID if you
               prefer to manage its access directly or retain the service ID after your
               secret expires, is rotated, or deleted. If you provide a service ID, do not
               include the `access_groups` parameter.
        :param bool reuse_api_key: (optional) Determines whether to use the same
               service ID and API key for future read operations on an
               `iam_credentials` secret.
               If set to `true`, the service reuses the current credentials. If set to
               `false`, a new service ID and API key are generated each time that the
               secret is read or accessed.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.ttl = ttl
        self.access_groups = access_groups
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.service_id = service_id
        self.service_id_is_static = service_id_is_static
        self.reuse_api_key = reuse_api_key
        self.next_rotation_date = next_rotation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretResource':
        """Initialize a IAMCredentialsSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in IAMCredentialsSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'access_groups' in _dict:
            args['access_groups'] = _dict.get('access_groups')
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        if 'api_key_id' in _dict:
            args['api_key_id'] = _dict.get('api_key_id')
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        if 'service_id_is_static' in _dict:
            args['service_id_is_static'] = _dict.get('service_id_is_static')
        if 'reuse_api_key' in _dict:
            args['reuse_api_key'] = _dict.get('reuse_api_key')
        if 'next_rotation_date' in _dict:
            args['next_rotation_date'] = string_to_datetime(_dict.get('next_rotation_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'access_groups') and self.access_groups is not None:
            _dict['access_groups'] = self.access_groups
        if hasattr(self, 'api_key') and getattr(self, 'api_key') is not None:
            _dict['api_key'] = getattr(self, 'api_key')
        if hasattr(self, 'api_key_id') and getattr(self, 'api_key_id') is not None:
            _dict['api_key_id'] = getattr(self, 'api_key_id')
        if hasattr(self, 'service_id') and self.service_id is not None:
            _dict['service_id'] = self.service_id
        if hasattr(self, 'service_id_is_static') and getattr(self, 'service_id_is_static') is not None:
            _dict['service_id_is_static'] = getattr(self, 'service_id_is_static')
        if hasattr(self, 'reuse_api_key') and self.reuse_api_key is not None:
            _dict['reuse_api_key'] = self.reuse_api_key
        if hasattr(self, 'next_rotation_date') and getattr(self, 'next_rotation_date') is not None:
            _dict['next_rotation_date'] = datetime_to_string(getattr(self, 'next_rotation_date'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class IAMCredentialsSecretVersion(SecretVersion):
    """
    IAMCredentialsSecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version. The data object contains the following fields:
          - `api_key`: The API key that is generated for this secret.
          - `api_key_id`: The ID of the API key that is generated for this secret.
          - `service_id`: The service ID under which the API key is created.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a IAMCredentialsSecretVersion object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        :param dict secret_data: (optional) The data that is associated with the
               secret version. The data object contains the following fields:
               - `api_key`: The API key that is generated for this secret.
               - `api_key_id`: The ID of the API key that is generated for this secret.
               - `service_id`: The service ID under which the API key is created.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretVersion':
        """Initialize a IAMCredentialsSecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        if hasattr(self, 'secret_data') and self.secret_data is not None:
            _dict['secret_data'] = self.secret_data
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IAMCredentialsSecretVersionInfo(SecretVersionInfo):
    """
    IAMCredentialsSecretVersionInfo.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a IAMCredentialsSecretVersionInfo object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretVersionInfo':
        """Initialize a IAMCredentialsSecretVersionInfo object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretVersionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretVersionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretVersionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretVersionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IAMCredentialsSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a IAMCredentialsSecretVersionMetadata object.

        :param str id: (optional) The v4 UUID that uniquely identifies the secret.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretVersionMetadata':
        """Initialize a IAMCredentialsSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IAMCredentialsSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IAMCredentialsSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IAMCredentialsSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IntermediateCertificateAuthoritiesConfig(GetConfigElementsResourcesItem):
    """
    Intermediate certificate authorities configuration.

    :attr List[IntermediateCertificateAuthoritiesConfigItem]
          intermediate_certificate_authorities:
    """

    def __init__(self,
                 intermediate_certificate_authorities: List['IntermediateCertificateAuthoritiesConfigItem']) -> None:
        """
        Initialize a IntermediateCertificateAuthoritiesConfig object.

        :param List[IntermediateCertificateAuthoritiesConfigItem]
               intermediate_certificate_authorities:
        """
        # pylint: disable=super-init-not-called
        self.intermediate_certificate_authorities = intermediate_certificate_authorities

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IntermediateCertificateAuthoritiesConfig':
        """Initialize a IntermediateCertificateAuthoritiesConfig object from a json dictionary."""
        args = {}
        if 'intermediate_certificate_authorities' in _dict:
            args['intermediate_certificate_authorities'] = [IntermediateCertificateAuthoritiesConfigItem.from_dict(v)
                                                            for v in _dict.get('intermediate_certificate_authorities')]
        else:
            raise ValueError(
                'Required property \'intermediate_certificate_authorities\' not present in IntermediateCertificateAuthoritiesConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IntermediateCertificateAuthoritiesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self,
                   'intermediate_certificate_authorities') and self.intermediate_certificate_authorities is not None:
            intermediate_certificate_authorities_list = []
            for v in self.intermediate_certificate_authorities:
                if isinstance(v, dict):
                    intermediate_certificate_authorities_list.append(v)
                else:
                    intermediate_certificate_authorities_list.append(v.to_dict())
            _dict['intermediate_certificate_authorities'] = intermediate_certificate_authorities_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IntermediateCertificateAuthoritiesConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IntermediateCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IntermediateCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class IntermediateCertificateAuthorityConfig(ConfigElementDefConfig):
    """
    Intermediate certificate authority configuration.

    :attr object max_ttl: The maximum time-to-live (TTL) for certificates that are
          created by this CA.
          The value can be supplied as a string representation of a duration in hours, for
          example '8760h'. In the API response, this value is returned in seconds
          (integer).
          Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
    :attr str signing_method: The signing method to use with this certificate
          authority to generate private certificates.
          You can choose between internal or externally signed options. For more
          information, see the
          [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-intermediate-certificate-authorities).
    :attr str issuer: (optional) The certificate authority that signed and issued
          the certificate.
          If the certificate is signed internally, the `issuer` field is required and must
          match the name of a certificate authority that is configured in the Secrets
          Manager service instance.
    :attr object crl_expiry: (optional) The time until the certificate revocation
          list (CRL) expires.
          The value can be supplied as a string representation of a duration in hours,
          such as `48h`. The default is 72 hours. In the API response, this value is
          returned in seconds (integer).
          **Note:** The CRL is rotated automatically before it expires.
    :attr bool crl_disable: (optional) Disables or enables certificate revocation
          list (CRL) building.
          If CRL building is disabled, a signed but zero-length CRL is returned when
          downloading the CRL. If CRL building is enabled,  it will rebuild the CRL.
    :attr bool crl_distribution_points_encoded: (optional) Determines whether to
          encode the certificate revocation list (CRL) distribution points in the
          certificates that are issued by this certificate authority.
    :attr bool issuing_certificates_urls_encoded: (optional) Determines whether to
          encode the URL of the issuing certificate in the certificates that are issued by
          this certificate authority.
    :attr str common_name: The fully qualified domain name or host domain name for
          the certificate.
    :attr str status: (optional) The status of the certificate authority. The status
          of a root certificate authority is either `configured` or `expired`. For
          intermediate certificate authorities, possible statuses include
          `signing_required`,
          `signed_certificate_required`, `certificate_template_required`, `configured`,
          `expired` or `revoked`.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr str format: (optional) The format of the returned data.
    :attr str private_key_format: (optional) The format of the generated private
          key.
    :attr str key_type: (optional) The type of private key to generate.
    :attr int key_bits: (optional) The number of bits to use when generating the
          private key.
          Allowable values for RSA keys are: `2048` and `4096`. Allowable values for EC
          keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is `2048`.
          The default for EC keys is `256`.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr dict data: (optional) The data that is associated with the intermediate
          certificate authority. The data object contains the
           following fields:
          - `csr`: The PEM-encoded certificate signing request.
          - `private_key`: The private key.
          - `private_key_type`: The type of private key, for example `rsa`.
    """

    def __init__(self,
                 max_ttl: object,
                 signing_method: str,
                 common_name: str,
                 *,
                 issuer: str = None,
                 crl_expiry: object = None,
                 crl_disable: bool = None,
                 crl_distribution_points_encoded: bool = None,
                 issuing_certificates_urls_encoded: bool = None,
                 status: str = None,
                 expiration_date: datetime = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 format: str = None,
                 private_key_format: str = None,
                 key_type: str = None,
                 key_bits: int = None,
                 exclude_cn_from_sans: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None,
                 data: dict = None) -> None:
        """
        Initialize a IntermediateCertificateAuthorityConfig object.

        :param object max_ttl: The maximum time-to-live (TTL) for certificates that
               are created by this CA.
               The value can be supplied as a string representation of a duration in
               hours, for example '8760h'. In the API response, this value is returned in
               seconds (integer).
               Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
        :param str signing_method: The signing method to use with this certificate
               authority to generate private certificates.
               You can choose between internal or externally signed options. For more
               information, see the
               [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-intermediate-certificate-authorities).
        :param str common_name: The fully qualified domain name or host domain name
               for the certificate.
        :param str issuer: (optional) The certificate authority that signed and
               issued the certificate.
               If the certificate is signed internally, the `issuer` field is required and
               must match the name of a certificate authority that is configured in the
               Secrets Manager service instance.
        :param object crl_expiry: (optional) The time until the certificate
               revocation list (CRL) expires.
               The value can be supplied as a string representation of a duration in
               hours, such as `48h`. The default is 72 hours. In the API response, this
               value is returned in seconds (integer).
               **Note:** The CRL is rotated automatically before it expires.
        :param bool crl_disable: (optional) Disables or enables certificate
               revocation list (CRL) building.
               If CRL building is disabled, a signed but zero-length CRL is returned when
               downloading the CRL. If CRL building is enabled,  it will rebuild the CRL.
        :param bool crl_distribution_points_encoded: (optional) Determines whether
               to encode the certificate revocation list (CRL) distribution points in the
               certificates that are issued by this certificate authority.
        :param bool issuing_certificates_urls_encoded: (optional) Determines
               whether to encode the URL of the issuing certificate in the certificates
               that are issued by this certificate authority.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param str format: (optional) The format of the returned data.
        :param str private_key_format: (optional) The format of the generated
               private key.
        :param str key_type: (optional) The type of private key to generate.
        :param int key_bits: (optional) The number of bits to use when generating
               the private key.
               Allowable values for RSA keys are: `2048` and `4096`. Allowable values for
               EC keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is
               `2048`. The default for EC keys is `256`.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.max_ttl = max_ttl
        self.signing_method = signing_method
        self.issuer = issuer
        self.crl_expiry = crl_expiry
        self.crl_disable = crl_disable
        self.crl_distribution_points_encoded = crl_distribution_points_encoded
        self.issuing_certificates_urls_encoded = issuing_certificates_urls_encoded
        self.common_name = common_name
        self.status = status
        self.expiration_date = expiration_date
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.format = format
        self.private_key_format = private_key_format
        self.key_type = key_type
        self.key_bits = key_bits
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.data = data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IntermediateCertificateAuthorityConfig':
        """Initialize a IntermediateCertificateAuthorityConfig object from a json dictionary."""
        args = {}
        if 'max_ttl' in _dict:
            args['max_ttl'] = _dict.get('max_ttl')
        else:
            raise ValueError('Required property \'max_ttl\' not present in IntermediateCertificateAuthorityConfig JSON')
        if 'signing_method' in _dict:
            args['signing_method'] = _dict.get('signing_method')
        else:
            raise ValueError(
                'Required property \'signing_method\' not present in IntermediateCertificateAuthorityConfig JSON')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'crl_expiry' in _dict:
            args['crl_expiry'] = _dict.get('crl_expiry')
        if 'crl_disable' in _dict:
            args['crl_disable'] = _dict.get('crl_disable')
        if 'crl_distribution_points_encoded' in _dict:
            args['crl_distribution_points_encoded'] = _dict.get('crl_distribution_points_encoded')
        if 'issuing_certificates_urls_encoded' in _dict:
            args['issuing_certificates_urls_encoded'] = _dict.get('issuing_certificates_urls_encoded')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        else:
            raise ValueError(
                'Required property \'common_name\' not present in IntermediateCertificateAuthorityConfig JSON')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'private_key_format' in _dict:
            args['private_key_format'] = _dict.get('private_key_format')
        if 'key_type' in _dict:
            args['key_type'] = _dict.get('key_type')
        if 'key_bits' in _dict:
            args['key_bits'] = _dict.get('key_bits')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'data' in _dict:
            args['data'] = _dict.get('data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IntermediateCertificateAuthorityConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'max_ttl') and self.max_ttl is not None:
            _dict['max_ttl'] = self.max_ttl
        if hasattr(self, 'signing_method') and self.signing_method is not None:
            _dict['signing_method'] = self.signing_method
        if hasattr(self, 'issuer') and self.issuer is not None:
            _dict['issuer'] = self.issuer
        if hasattr(self, 'crl_expiry') and self.crl_expiry is not None:
            _dict['crl_expiry'] = self.crl_expiry
        if hasattr(self, 'crl_disable') and self.crl_disable is not None:
            _dict['crl_disable'] = self.crl_disable
        if hasattr(self, 'crl_distribution_points_encoded') and self.crl_distribution_points_encoded is not None:
            _dict['crl_distribution_points_encoded'] = self.crl_distribution_points_encoded
        if hasattr(self, 'issuing_certificates_urls_encoded') and self.issuing_certificates_urls_encoded is not None:
            _dict['issuing_certificates_urls_encoded'] = self.issuing_certificates_urls_encoded
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'status') and getattr(self, 'status') is not None:
            _dict['status'] = getattr(self, 'status')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'private_key_format') and self.private_key_format is not None:
            _dict['private_key_format'] = self.private_key_format
        if hasattr(self, 'key_type') and self.key_type is not None:
            _dict['key_type'] = self.key_type
        if hasattr(self, 'key_bits') and self.key_bits is not None:
            _dict['key_bits'] = self.key_bits
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'data') and getattr(self, 'data') is not None:
            _dict['data'] = getattr(self, 'data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this IntermediateCertificateAuthorityConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'IntermediateCertificateAuthorityConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'IntermediateCertificateAuthorityConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SigningMethodEnum(str, Enum):
        """
        The signing method to use with this certificate authority to generate private
        certificates.
        You can choose between internal or externally signed options. For more
        information, see the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-intermediate-certificate-authorities).
        """
        INTERNAL = 'internal'
        EXTERNAL = 'external'

    class StatusEnum(str, Enum):
        """
        The status of the certificate authority. The status of a root certificate
        authority is either `configured` or `expired`. For intermediate certificate
        authorities, possible statuses include `signing_required`,
        `signed_certificate_required`, `certificate_template_required`, `configured`,
        `expired` or `revoked`.
        """
        SIGNING_REQUIRED = 'signing_required'
        SIGNED_CERTIFICATE_REQUIRED = 'signed_certificate_required'
        CERTIFICATE_TEMPLATE_REQUIRED = 'certificate_template_required'
        CONFIGURED = 'configured'
        EXPIRED = 'expired'
        REVOKED = 'revoked'

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'

    class PrivateKeyFormatEnum(str, Enum):
        """
        The format of the generated private key.
        """
        DER = 'der'
        PKCS8 = 'pkcs8'

    class KeyTypeEnum(str, Enum):
        """
        The type of private key to generate.
        """
        RSA = 'rsa'
        EC = 'ec'


class KvSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a key-value secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None) -> None:
        """
        Initialize a KvSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'KvSecretMetadata':
        """Initialize a KvSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in KvSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KvSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KvSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'KvSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'KvSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class KvSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr dict payload: (optional) The new secret data to assign to the secret.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version.
          The data object contains the field `payload`.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 expiration_date: datetime = None,
                 payload: dict = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a KvSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        :param dict payload: (optional) The new secret data to assign to the
               secret.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.expiration_date = expiration_date
        self.payload = payload
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'KvSecretResource':
        """Initialize a KvSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in KvSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a KvSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        if hasattr(self, 'payload') and self.payload is not None:
            _dict['payload'] = self.payload
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this KvSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'KvSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'KvSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class PrivateCertPolicyRotation(SecretPolicyRotationRotation):
    """
    The `private_cert` secret rotation policy.

    :attr bool auto_rotate:
    :attr int interval: (optional) The length of the secret rotation time interval.
    :attr str unit: (optional) The units for the secret rotation time interval.
    """

    def __init__(self,
                 auto_rotate: bool,
                 *,
                 interval: int = None,
                 unit: str = None) -> None:
        """
        Initialize a PrivateCertPolicyRotation object.

        :param bool auto_rotate:
        :param int interval: (optional) The length of the secret rotation time
               interval.
        :param str unit: (optional) The units for the secret rotation time
               interval.
        """
        # pylint: disable=super-init-not-called
        self.auto_rotate = auto_rotate
        self.interval = interval
        self.unit = unit

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertPolicyRotation':
        """Initialize a PrivateCertPolicyRotation object from a json dictionary."""
        args = {}
        if 'auto_rotate' in _dict:
            args['auto_rotate'] = _dict.get('auto_rotate')
        else:
            raise ValueError('Required property \'auto_rotate\' not present in PrivateCertPolicyRotation JSON')
        if 'interval' in _dict:
            args['interval'] = _dict.get('interval')
        if 'unit' in _dict:
            args['unit'] = _dict.get('unit')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_rotate') and self.auto_rotate is not None:
            _dict['auto_rotate'] = self.auto_rotate
        if hasattr(self, 'interval') and self.interval is not None:
            _dict['interval'] = self.interval
        if hasattr(self, 'unit') and self.unit is not None:
            _dict['unit'] = self.unit
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class UnitEnum(str, Enum):
        """
        The units for the secret rotation time interval.
        """
        DAY = 'day'
        MONTH = 'month'


class PrivateCertSecretEngineRootConfig(GetConfigResourcesItem):
    """
    Configuration for the private certificates engine.

    :attr List[RootCertificateAuthoritiesConfigItem] root_certificate_authorities:
          (optional) The root certificate authority configurations that are associated
          with your instance.
    :attr List[IntermediateCertificateAuthoritiesConfigItem]
          intermediate_certificate_authorities: (optional) The intermediate certificate
          authority configurations that are associated with your instance.
    :attr List[CertificateTemplatesConfigItem] certificate_templates: (optional) The
          certificate templates that are associated with your instance.
    """

    def __init__(self,
                 *,
                 root_certificate_authorities: List['RootCertificateAuthoritiesConfigItem'] = None,
                 intermediate_certificate_authorities: List['IntermediateCertificateAuthoritiesConfigItem'] = None,
                 certificate_templates: List['CertificateTemplatesConfigItem'] = None) -> None:
        """
        Initialize a PrivateCertSecretEngineRootConfig object.

        """
        # pylint: disable=super-init-not-called
        self.root_certificate_authorities = root_certificate_authorities
        self.intermediate_certificate_authorities = intermediate_certificate_authorities
        self.certificate_templates = certificate_templates

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertSecretEngineRootConfig':
        """Initialize a PrivateCertSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'root_certificate_authorities' in _dict:
            args['root_certificate_authorities'] = [RootCertificateAuthoritiesConfigItem.from_dict(v) for v in
                                                    _dict.get('root_certificate_authorities')]
        if 'intermediate_certificate_authorities' in _dict:
            args['intermediate_certificate_authorities'] = [IntermediateCertificateAuthoritiesConfigItem.from_dict(v)
                                                            for v in _dict.get('intermediate_certificate_authorities')]
        if 'certificate_templates' in _dict:
            args['certificate_templates'] = [CertificateTemplatesConfigItem.from_dict(v) for v in
                                             _dict.get('certificate_templates')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertSecretEngineRootConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'root_certificate_authorities') and getattr(self, 'root_certificate_authorities') is not None:
            root_certificate_authorities_list = []
            for v in getattr(self, 'root_certificate_authorities'):
                if isinstance(v, dict):
                    root_certificate_authorities_list.append(v)
                else:
                    root_certificate_authorities_list.append(v.to_dict())
            _dict['root_certificate_authorities'] = root_certificate_authorities_list
        if hasattr(self, 'intermediate_certificate_authorities') and getattr(self,
                                                                             'intermediate_certificate_authorities') is not None:
            intermediate_certificate_authorities_list = []
            for v in getattr(self, 'intermediate_certificate_authorities'):
                if isinstance(v, dict):
                    intermediate_certificate_authorities_list.append(v)
                else:
                    intermediate_certificate_authorities_list.append(v.to_dict())
            _dict['intermediate_certificate_authorities'] = intermediate_certificate_authorities_list
        if hasattr(self, 'certificate_templates') and getattr(self, 'certificate_templates') is not None:
            certificate_templates_list = []
            for v in getattr(self, 'certificate_templates'):
                if isinstance(v, dict):
                    certificate_templates_list.append(v)
                else:
                    certificate_templates_list.append(v.to_dict())
            _dict['certificate_templates'] = certificate_templates_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertSecretEngineRootConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class PrivateCertificateSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a private certificate secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr str certificate_template: (optional) The name of the certificate template.
    :attr str certificate_authority: (optional) The intermediate certificate
          authority that signed this certificate.
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr List[str] alt_names: (optional) The alternative names that are defined for
          the certificate.
    :attr Rotation rotation: (optional)
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          that was used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public and private keys that are
          associated with the certificate.
    :attr str issuer: (optional) The certificate authority that signed and issued
          the certificate.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr int revocation_time: (optional) The timestamp of the certificate
          revocation.
    :attr datetime revocation_time_rfc3339: (optional) The date and time that the
          certificate was revoked. The date format follows RFC 3339.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 certificate_template: str = None,
                 certificate_authority: str = None,
                 common_name: str = None,
                 alt_names: List[str] = None,
                 rotation: 'Rotation' = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 issuer: str = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 revocation_time: int = None,
                 revocation_time_rfc3339: datetime = None) -> None:
        """
        Initialize a PrivateCertificateSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param Rotation rotation: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.certificate_template = certificate_template
        self.certificate_authority = certificate_authority
        self.common_name = common_name
        self.alt_names = alt_names
        self.rotation = rotation
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.issuer = issuer
        self.validity = validity
        self.serial_number = serial_number
        self.revocation_time = revocation_time
        self.revocation_time_rfc3339 = revocation_time_rfc3339

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertificateSecretMetadata':
        """Initialize a PrivateCertificateSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in PrivateCertificateSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'certificate_template' in _dict:
            args['certificate_template'] = _dict.get('certificate_template')
        if 'certificate_authority' in _dict:
            args['certificate_authority'] = _dict.get('certificate_authority')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        if 'revocation_time_rfc3339' in _dict:
            args['revocation_time_rfc3339'] = string_to_datetime(_dict.get('revocation_time_rfc3339'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertificateSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'certificate_template') and getattr(self, 'certificate_template') is not None:
            _dict['certificate_template'] = getattr(self, 'certificate_template')
        if hasattr(self, 'certificate_authority') and getattr(self, 'certificate_authority') is not None:
            _dict['certificate_authority'] = getattr(self, 'certificate_authority')
        if hasattr(self, 'common_name') and getattr(self, 'common_name') is not None:
            _dict['common_name'] = getattr(self, 'common_name')
        if hasattr(self, 'alt_names') and getattr(self, 'alt_names') is not None:
            _dict['alt_names'] = getattr(self, 'alt_names')
        if hasattr(self, 'rotation') and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and getattr(self, 'key_algorithm') is not None:
            _dict['key_algorithm'] = getattr(self, 'key_algorithm')
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'revocation_time') and getattr(self, 'revocation_time') is not None:
            _dict['revocation_time'] = getattr(self, 'revocation_time')
        if hasattr(self, 'revocation_time_rfc3339') and getattr(self, 'revocation_time_rfc3339') is not None:
            _dict['revocation_time_rfc3339'] = datetime_to_string(getattr(self, 'revocation_time_rfc3339'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertificateSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertificateSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertificateSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class PrivateCertificateSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str certificate_template: The name of the certificate template.
    :attr str certificate_authority: (optional) The intermediate certificate
          authority that signed this certificate.
    :attr str csr: (optional) The certificate signing request. If you don't include
          this parameter, the CSR that is used to generate the certificate is created
          internally. If you provide a CSR, it is used also for auto rotation and manual
          rotation,  unless you provide another CSR in the manual rotation request.
    :attr str common_name: The fully qualified domain name or host domain name for
          the certificate. If you provide a CSR that includes a common name value, the
          certificate is generated with the common name that is provided in the CSR.
    :attr object alt_names: (optional) The alternative names that are defined for
          the certificate.
          For public certificates, this value is provided as an array of strings. For
          private certificates, this value is provided as a comma-delimited list (string).
          In the API response, this value is returned as an array of strings for all the
          types of certificate secrets.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration in hours, for
          example '12h'. The value can't exceed the `max_ttl` that is defined in the
          associated certificate template.
    :attr str format: (optional) The format of the returned data.
    :attr str private_key_format: (optional) The format of the generated private
          key.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr Rotation rotation: (optional)
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          that was used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public and private keys that are
          associated with the certificate.
    :attr str issuer: (optional) The certificate authority that signed and issued
          the certificate.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr int revocation_time: (optional) The timestamp of the certificate
          revocation.
    :attr datetime revocation_time_rfc3339: (optional) The date and time that the
          certificate was revoked. The date format follows RFC 3339.
    :attr dict secret_data: (optional) The data that is associated with the secret.
          The data object contains the following fields:
          - `certificate`: The contents of the certificate.
          - `private_key`: The private key that is associated with the certificate. If you
          provide a CSR in the request, the private_key field is not included in the data.
          - `issuing_ca`: The certificate of the certificate authority that signed and
          issued this certificate.
          - `ca_chain`: The chain of certificate authorities that are associated with the
          certificate.
    """

    def __init__(self,
                 name: str,
                 certificate_template: str,
                 common_name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 certificate_authority: str = None,
                 csr: str = None,
                 alt_names: object = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 private_key_format: str = None,
                 exclude_cn_from_sans: bool = None,
                 rotation: 'Rotation' = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 issuer: str = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 revocation_time: int = None,
                 revocation_time_rfc3339: datetime = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a PrivateCertificateSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str certificate_template: The name of the certificate template.
        :param str common_name: The fully qualified domain name or host domain name
               for the certificate. If you provide a CSR that includes a common name
               value, the certificate is generated with the common name that is provided
               in the CSR.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param str csr: (optional) The certificate signing request. If you don't
               include this parameter, the CSR that is used to generate the certificate is
               created internally. If you provide a CSR, it is used also for auto rotation
               and manual rotation,  unless you provide another CSR in the manual rotation
               request.
        :param object alt_names: (optional) The alternative names that are defined
               for the certificate.
               For public certificates, this value is provided as an array of strings. For
               private certificates, this value is provided as a comma-delimited list
               (string). In the API response, this value is returned as an array of
               strings for all the types of certificate secrets.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration in
               hours, for example '12h'. The value can't exceed the `max_ttl` that is
               defined in the associated certificate template.
        :param str format: (optional) The format of the returned data.
        :param str private_key_format: (optional) The format of the generated
               private key.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param Rotation rotation: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.certificate_template = certificate_template
        self.certificate_authority = certificate_authority
        self.csr = csr
        self.common_name = common_name
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.private_key_format = private_key_format
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.rotation = rotation
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.issuer = issuer
        self.validity = validity
        self.serial_number = serial_number
        self.revocation_time = revocation_time
        self.revocation_time_rfc3339 = revocation_time_rfc3339
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertificateSecretResource':
        """Initialize a PrivateCertificateSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in PrivateCertificateSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'certificate_template' in _dict:
            args['certificate_template'] = _dict.get('certificate_template')
        else:
            raise ValueError(
                'Required property \'certificate_template\' not present in PrivateCertificateSecretResource JSON')
        if 'certificate_authority' in _dict:
            args['certificate_authority'] = _dict.get('certificate_authority')
        if 'csr' in _dict:
            args['csr'] = _dict.get('csr')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        else:
            raise ValueError('Required property \'common_name\' not present in PrivateCertificateSecretResource JSON')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'private_key_format' in _dict:
            args['private_key_format'] = _dict.get('private_key_format')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        if 'revocation_time_rfc3339' in _dict:
            args['revocation_time_rfc3339'] = string_to_datetime(_dict.get('revocation_time_rfc3339'))
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertificateSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'certificate_template') and self.certificate_template is not None:
            _dict['certificate_template'] = self.certificate_template
        if hasattr(self, 'certificate_authority') and getattr(self, 'certificate_authority') is not None:
            _dict['certificate_authority'] = getattr(self, 'certificate_authority')
        if hasattr(self, 'csr') and self.csr is not None:
            _dict['csr'] = self.csr
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'private_key_format') and self.private_key_format is not None:
            _dict['private_key_format'] = self.private_key_format
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'rotation') and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and getattr(self, 'key_algorithm') is not None:
            _dict['key_algorithm'] = getattr(self, 'key_algorithm')
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'revocation_time') and getattr(self, 'revocation_time') is not None:
            _dict['revocation_time'] = getattr(self, 'revocation_time')
        if hasattr(self, 'revocation_time_rfc3339') and getattr(self, 'revocation_time_rfc3339') is not None:
            _dict['revocation_time_rfc3339'] = datetime_to_string(getattr(self, 'revocation_time_rfc3339'))
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertificateSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertificateSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertificateSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'

    class PrivateKeyFormatEnum(str, Enum):
        """
        The format of the generated private key.
        """
        DER = 'der'
        PKCS8 = 'pkcs8'


class PrivateCertificateSecretVersion(SecretVersion):
    """
    PrivateCertificateSecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateSecretData secret_data: (optional) The data that is associated
          with the secret version. The data object contains the following fields:
          - `certificate`: The contents of the certificate.
          - `private_key`: The private key that is associated with the certificate.
          - `intermediate`: The intermediate certificate that is associated with the
          certificate.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr int revocation_time: (optional) The timestamp of the certificate
          revocation.
    :attr datetime revocation_time_rfc3339: (optional) The date and time that the
          certificate was revoked. The date format follows RFC 3339.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 secret_data: 'CertificateSecretData' = None,
                 state: int = None,
                 state_description: str = None,
                 revocation_time: int = None,
                 revocation_time_rfc3339: datetime = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a PrivateCertificateSecretVersion object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.validity = validity
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.secret_data = secret_data
        self.state = state
        self.state_description = state_description
        self.revocation_time = revocation_time
        self.revocation_time_rfc3339 = revocation_time_rfc3339
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertificateSecretVersion':
        """Initialize a PrivateCertificateSecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'secret_data' in _dict:
            args['secret_data'] = CertificateSecretData.from_dict(_dict.get('secret_data'))
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        if 'revocation_time_rfc3339' in _dict:
            args['revocation_time_rfc3339'] = string_to_datetime(_dict.get('revocation_time_rfc3339'))
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertificateSecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            if isinstance(getattr(self, 'secret_data'), dict):
                _dict['secret_data'] = getattr(self, 'secret_data')
            else:
                _dict['secret_data'] = getattr(self, 'secret_data').to_dict()
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'revocation_time') and getattr(self, 'revocation_time') is not None:
            _dict['revocation_time'] = getattr(self, 'revocation_time')
        if hasattr(self, 'revocation_time_rfc3339') and getattr(self, 'revocation_time_rfc3339') is not None:
            _dict['revocation_time_rfc3339'] = datetime_to_string(getattr(self, 'revocation_time_rfc3339'))
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertificateSecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertificateSecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertificateSecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class PrivateCertificateSecretVersionInfo(SecretVersionInfo):
    """
    PrivateCertificateSecretVersionInfo.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateValidity validity: (optional)
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr int revocation_time: (optional) The timestamp of the certificate
          revocation.
    :attr datetime revocation_time_rfc3339: (optional) The date and time that the
          certificate was revoked. The date format follows RFC 3339.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 version_custom_metadata: dict = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 validity: 'CertificateValidity' = None,
                 state: int = None,
                 state_description: str = None,
                 revocation_time: int = None,
                 revocation_time_rfc3339: datetime = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a PrivateCertificateSecretVersionInfo object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.version_custom_metadata = version_custom_metadata
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.validity = validity
        self.state = state
        self.state_description = state_description
        self.revocation_time = revocation_time
        self.revocation_time_rfc3339 = revocation_time_rfc3339
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertificateSecretVersionInfo':
        """Initialize a PrivateCertificateSecretVersionInfo object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        if 'revocation_time_rfc3339' in _dict:
            args['revocation_time_rfc3339'] = string_to_datetime(_dict.get('revocation_time_rfc3339'))
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertificateSecretVersionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'revocation_time') and getattr(self, 'revocation_time') is not None:
            _dict['revocation_time'] = getattr(self, 'revocation_time')
        if hasattr(self, 'revocation_time_rfc3339') and getattr(self, 'revocation_time_rfc3339') is not None:
            _dict['revocation_time_rfc3339'] = datetime_to_string(getattr(self, 'revocation_time_rfc3339'))
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertificateSecretVersionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertificateSecretVersionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertificateSecretVersionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class PrivateCertificateSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateValidity validity: (optional)
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr int revocation_time: (optional) The timestamp of the certificate
          revocation.
    :attr datetime revocation_time_rfc3339: (optional) The date and time that the
          certificate was revoked. The date format follows RFC 3339.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 validity: 'CertificateValidity' = None,
                 state: int = None,
                 state_description: str = None,
                 revocation_time: int = None,
                 revocation_time_rfc3339: datetime = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a PrivateCertificateSecretVersionMetadata object.

        :param str id: (optional) The v4 UUID that uniquely identifies the secret.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.validity = validity
        self.state = state
        self.state_description = state_description
        self.revocation_time = revocation_time
        self.revocation_time_rfc3339 = revocation_time_rfc3339
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PrivateCertificateSecretVersionMetadata':
        """Initialize a PrivateCertificateSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        if 'revocation_time_rfc3339' in _dict:
            args['revocation_time_rfc3339'] = string_to_datetime(_dict.get('revocation_time_rfc3339'))
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PrivateCertificateSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'revocation_time') and getattr(self, 'revocation_time') is not None:
            _dict['revocation_time'] = getattr(self, 'revocation_time')
        if hasattr(self, 'revocation_time_rfc3339') and getattr(self, 'revocation_time_rfc3339') is not None:
            _dict['revocation_time_rfc3339'] = datetime_to_string(getattr(self, 'revocation_time_rfc3339'))
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PrivateCertificateSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PrivateCertificateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PrivateCertificateSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class PublicCertSecretEngineRootConfig(GetConfigResourcesItem):
    """
    Configuration for the public certificates engine.

    :attr List[ConfigElementMetadata] certificate_authorities: (optional) The
          certificate authority configurations that are associated with your instance.
    :attr List[ConfigElementMetadata] dns_providers: (optional) The DNS provider
          configurations that are associated with your instance.
    """

    def __init__(self,
                 *,
                 certificate_authorities: List['ConfigElementMetadata'] = None,
                 dns_providers: List['ConfigElementMetadata'] = None) -> None:
        """
        Initialize a PublicCertSecretEngineRootConfig object.

        :param List[ConfigElementMetadata] dns_providers: (optional) The DNS
               provider configurations that are associated with your instance.
        """
        # pylint: disable=super-init-not-called
        self.certificate_authorities = certificate_authorities
        self.dns_providers = dns_providers

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PublicCertSecretEngineRootConfig':
        """Initialize a PublicCertSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'certificate_authorities' in _dict:
            args['certificate_authorities'] = [ConfigElementMetadata.from_dict(v) for v in
                                               _dict.get('certificate_authorities')]
        if 'dns_providers' in _dict:
            args['dns_providers'] = [ConfigElementMetadata.from_dict(v) for v in _dict.get('dns_providers')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PublicCertSecretEngineRootConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_authorities') and getattr(self, 'certificate_authorities') is not None:
            certificate_authorities_list = []
            for v in getattr(self, 'certificate_authorities'):
                if isinstance(v, dict):
                    certificate_authorities_list.append(v)
                else:
                    certificate_authorities_list.append(v.to_dict())
            _dict['certificate_authorities'] = certificate_authorities_list
        if hasattr(self, 'dns_providers') and self.dns_providers is not None:
            dns_providers_list = []
            for v in self.dns_providers:
                if isinstance(v, dict):
                    dns_providers_list.append(v)
                else:
                    dns_providers_list.append(v.to_dict())
            _dict['dns_providers'] = dns_providers_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PublicCertSecretEngineRootConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PublicCertSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PublicCertSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class PublicCertificateSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a public certificate secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr bool bundle_certs: (optional) Determines whether your issued certificate
          is bundled with intermediate certificates.
          Set to `false` for the certificate file to contain only the issued certificate.
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          to be used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm to be used to generate the public key that is associated with the
          certificate.
    :attr List[str] alt_names: (optional) The alternative names that are defined for
          the certificate.
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr bool intermediate_included: (optional) Indicates whether the certificate
          was ordered with an associated intermediate certificate.
    :attr bool private_key_included: (optional) Indicates whether the certificate
          was ordered with an associated private key.
    :attr Rotation rotation: (optional)
    :attr IssuanceInfo issuance_info: (optional) Issuance information that is
          associated with your certificate.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 issuer: str = None,
                 bundle_certs: bool = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 alt_names: List[str] = None,
                 common_name: str = None,
                 intermediate_included: bool = None,
                 private_key_included: bool = None,
                 rotation: 'Rotation' = None,
                 issuance_info: 'IssuanceInfo' = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None) -> None:
        """
        Initialize a PublicCertificateSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param bool bundle_certs: (optional) Determines whether your issued
               certificate is bundled with intermediate certificates.
               Set to `false` for the certificate file to contain only the issued
               certificate.
        :param str key_algorithm: (optional) The identifier for the cryptographic
               algorithm to be used to generate the public key that is associated with the
               certificate.
        :param List[str] alt_names: (optional) The alternative names that are
               defined for the certificate.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param Rotation rotation: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.issuer = issuer
        self.bundle_certs = bundle_certs
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.alt_names = alt_names
        self.common_name = common_name
        self.intermediate_included = intermediate_included
        self.private_key_included = private_key_included
        self.rotation = rotation
        self.issuance_info = issuance_info
        self.validity = validity
        self.serial_number = serial_number

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PublicCertificateSecretMetadata':
        """Initialize a PublicCertificateSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in PublicCertificateSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'bundle_certs' in _dict:
            args['bundle_certs'] = _dict.get('bundle_certs')
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'intermediate_included' in _dict:
            args['intermediate_included'] = _dict.get('intermediate_included')
        if 'private_key_included' in _dict:
            args['private_key_included'] = _dict.get('private_key_included')
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'issuance_info' in _dict:
            args['issuance_info'] = IssuanceInfo.from_dict(_dict.get('issuance_info'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PublicCertificateSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'bundle_certs') and self.bundle_certs is not None:
            _dict['bundle_certs'] = self.bundle_certs
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and self.key_algorithm is not None:
            _dict['key_algorithm'] = self.key_algorithm
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'intermediate_included') and getattr(self, 'intermediate_included') is not None:
            _dict['intermediate_included'] = getattr(self, 'intermediate_included')
        if hasattr(self, 'private_key_included') and getattr(self, 'private_key_included') is not None:
            _dict['private_key_included'] = getattr(self, 'private_key_included')
        if hasattr(self, 'rotation') and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'issuance_info') and getattr(self, 'issuance_info') is not None:
            if isinstance(getattr(self, 'issuance_info'), dict):
                _dict['issuance_info'] = getattr(self, 'issuance_info')
            else:
                _dict['issuance_info'] = getattr(self, 'issuance_info').to_dict()
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PublicCertificateSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PublicCertificateSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PublicCertificateSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'

    class KeyAlgorithmEnum(str, Enum):
        """
        The identifier for the cryptographic algorithm to be used to generate the public
        key that is associated with the certificate.
        """
        RSA2048 = 'RSA2048'
        RSA4096 = 'RSA4096'
        EC256 = 'EC256'
        EC384 = 'EC384'


class PublicCertificateSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr bool bundle_certs: (optional) Determines whether your issued certificate
          is bundled with intermediate certificates.
          Set to `false` for the certificate file to contain only the issued certificate.
    :attr str ca: (optional) The name of the certificate authority configuration.
          To view a list of your configured authorities, use the [List configurations
          API](#get-secret-config-element).
    :attr str dns: (optional) The name of the DNS provider configuration.
          To view a list of your configured authorities, use the [List configurations
          API](#get-secret-config-element).
    :attr str algorithm: (optional) The identifier for the cryptographic algorithm
          to be used by the issuing certificate authority to sign the certificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm to be used to generate the public key that is associated with the
          certificate.
          The algorithm that you select determines the encryption algorithm (`RSA` or
          `ECDSA`) and key size to be used to generate keys and sign certificates. For
          longer living certificates, it is recommended to use longer keys to provide more
          encryption protection.
    :attr object alt_names: (optional) The alternative names that are defined for
          the certificate.
          For public certificates, this value is provided as an array of strings. For
          private certificates, this value is provided as a comma-delimited list (string).
          In the API response, this value is returned as an array of strings for all the
          types of certificate secrets.
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr bool private_key_included: (optional) Indicates whether the issued
          certificate includes a private key.
    :attr bool intermediate_included: (optional) Indicates whether the issued
          certificate includes an intermediate certificate.
    :attr Rotation rotation: (optional)
    :attr IssuanceInfo issuance_info: (optional) Issuance information that is
          associated with your certificate.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr dict secret_data: (optional) The data that is associated with the secret.
          The data object contains the following fields:
          - `certificate`: The contents of the certificate.
          - `private_key`: The private key that is associated with the certificate.
          - `intermediate`: The intermediate certificate that is associated with the
          certificate.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 issuer: str = None,
                 bundle_certs: bool = None,
                 ca: str = None,
                 dns: str = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 alt_names: object = None,
                 common_name: str = None,
                 private_key_included: bool = None,
                 intermediate_included: bool = None,
                 rotation: 'Rotation' = None,
                 issuance_info: 'IssuanceInfo' = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a PublicCertificateSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool bundle_certs: (optional) Determines whether your issued
               certificate is bundled with intermediate certificates.
               Set to `false` for the certificate file to contain only the issued
               certificate.
        :param str ca: (optional) The name of the certificate authority
               configuration.
               To view a list of your configured authorities, use the [List configurations
               API](#get-secret-config-element).
        :param str dns: (optional) The name of the DNS provider configuration.
               To view a list of your configured authorities, use the [List configurations
               API](#get-secret-config-element).
        :param str key_algorithm: (optional) The identifier for the cryptographic
               algorithm to be used to generate the public key that is associated with the
               certificate.
               The algorithm that you select determines the encryption algorithm (`RSA` or
               `ECDSA`) and key size to be used to generate keys and sign certificates.
               For longer living certificates, it is recommended to use longer keys to
               provide more encryption protection.
        :param object alt_names: (optional) The alternative names that are defined
               for the certificate.
               For public certificates, this value is provided as an array of strings. For
               private certificates, this value is provided as a comma-delimited list
               (string). In the API response, this value is returned as an array of
               strings for all the types of certificate secrets.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param Rotation rotation: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.issuer = issuer
        self.bundle_certs = bundle_certs
        self.ca = ca
        self.dns = dns
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.alt_names = alt_names
        self.common_name = common_name
        self.private_key_included = private_key_included
        self.intermediate_included = intermediate_included
        self.rotation = rotation
        self.issuance_info = issuance_info
        self.validity = validity
        self.serial_number = serial_number
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PublicCertificateSecretResource':
        """Initialize a PublicCertificateSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in PublicCertificateSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'issuer' in _dict:
            args['issuer'] = _dict.get('issuer')
        if 'bundle_certs' in _dict:
            args['bundle_certs'] = _dict.get('bundle_certs')
        if 'ca' in _dict:
            args['ca'] = _dict.get('ca')
        if 'dns' in _dict:
            args['dns'] = _dict.get('dns')
        if 'algorithm' in _dict:
            args['algorithm'] = _dict.get('algorithm')
        if 'key_algorithm' in _dict:
            args['key_algorithm'] = _dict.get('key_algorithm')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'private_key_included' in _dict:
            args['private_key_included'] = _dict.get('private_key_included')
        if 'intermediate_included' in _dict:
            args['intermediate_included'] = _dict.get('intermediate_included')
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'issuance_info' in _dict:
            args['issuance_info'] = IssuanceInfo.from_dict(_dict.get('issuance_info'))
        if 'validity' in _dict:
            args['validity'] = CertificateValidity.from_dict(_dict.get('validity'))
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PublicCertificateSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'bundle_certs') and self.bundle_certs is not None:
            _dict['bundle_certs'] = self.bundle_certs
        if hasattr(self, 'ca') and self.ca is not None:
            _dict['ca'] = self.ca
        if hasattr(self, 'dns') and self.dns is not None:
            _dict['dns'] = self.dns
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and self.key_algorithm is not None:
            _dict['key_algorithm'] = self.key_algorithm
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'private_key_included') and getattr(self, 'private_key_included') is not None:
            _dict['private_key_included'] = getattr(self, 'private_key_included')
        if hasattr(self, 'intermediate_included') and getattr(self, 'intermediate_included') is not None:
            _dict['intermediate_included'] = getattr(self, 'intermediate_included')
        if hasattr(self, 'rotation') and self.rotation is not None:
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'issuance_info') and getattr(self, 'issuance_info') is not None:
            if isinstance(getattr(self, 'issuance_info'), dict):
                _dict['issuance_info'] = getattr(self, 'issuance_info')
            else:
                _dict['issuance_info'] = getattr(self, 'issuance_info').to_dict()
        if hasattr(self, 'validity') and getattr(self, 'validity') is not None:
            if isinstance(getattr(self, 'validity'), dict):
                _dict['validity'] = getattr(self, 'validity')
            else:
                _dict['validity'] = getattr(self, 'validity').to_dict()
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PublicCertificateSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PublicCertificateSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PublicCertificateSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'

    class KeyAlgorithmEnum(str, Enum):
        """
        The identifier for the cryptographic algorithm to be used to generate the public
        key that is associated with the certificate.
        The algorithm that you select determines the encryption algorithm (`RSA` or
        `ECDSA`) and key size to be used to generate keys and sign certificates. For
        longer living certificates, it is recommended to use longer keys to provide more
        encryption protection.
        """
        RSA2048 = 'RSA2048'
        RSA4096 = 'RSA4096'
        EC256 = 'EC256'
        EC384 = 'EC384'


class RestoreIAMCredentialsSecretBody(SecretAction):
    """
    The request body of a `restore` action.

    :attr str version_id: The ID of the target version or the alias `previous`.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 version_id: str,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RestoreIAMCredentialsSecretBody object.

        :param str version_id: The ID of the target version or the alias
               `previous`.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.version_id = version_id
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RestoreIAMCredentialsSecretBody':
        """Initialize a RestoreIAMCredentialsSecretBody object from a json dictionary."""
        args = {}
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        else:
            raise ValueError('Required property \'version_id\' not present in RestoreIAMCredentialsSecretBody JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RestoreIAMCredentialsSecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'version_id') and self.version_id is not None:
            _dict['version_id'] = self.version_id
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RestoreIAMCredentialsSecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RestoreIAMCredentialsSecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RestoreIAMCredentialsSecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RevokeAction(ConfigAction):
    """
    A request to revoke the certificate of an internally signed intermediate certificate
    authority.

    :attr str serial_number: The serial number of the certificate.
    """

    def __init__(self,
                 serial_number: str) -> None:
        """
        Initialize a RevokeAction object.

        :param str serial_number: The serial number of the certificate.
        """
        # pylint: disable=super-init-not-called
        self.serial_number = serial_number

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RevokeAction':
        """Initialize a RevokeAction object from a json dictionary."""
        args = {}
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        else:
            raise ValueError('Required property \'serial_number\' not present in RevokeAction JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RevokeAction object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RevokeAction object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RevokeAction') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RevokeAction') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RevokeActionResult(ConfigElementActionResultConfig):
    """
    Properties that are returned with a successful `revoke` action.

    :attr int revocation_time: (optional) The time until the certificate authority
          is revoked.
    """

    def __init__(self,
                 *,
                 revocation_time: int = None) -> None:
        """
        Initialize a RevokeActionResult object.

        :param int revocation_time: (optional) The time until the certificate
               authority is revoked.
        """
        # pylint: disable=super-init-not-called
        self.revocation_time = revocation_time

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RevokeActionResult':
        """Initialize a RevokeActionResult object from a json dictionary."""
        args = {}
        if 'revocation_time' in _dict:
            args['revocation_time'] = _dict.get('revocation_time')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RevokeActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'revocation_time') and self.revocation_time is not None:
            _dict['revocation_time'] = self.revocation_time
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RevokeActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RevokeActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RevokeActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RootCertificateAuthoritiesConfig(GetConfigElementsResourcesItem):
    """
    Root certificate authorities configuration.

    :attr List[RootCertificateAuthoritiesConfigItem] root_certificate_authorities:
    """

    def __init__(self,
                 root_certificate_authorities: List['RootCertificateAuthoritiesConfigItem']) -> None:
        """
        Initialize a RootCertificateAuthoritiesConfig object.

        :param List[RootCertificateAuthoritiesConfigItem]
               root_certificate_authorities:
        """
        # pylint: disable=super-init-not-called
        self.root_certificate_authorities = root_certificate_authorities

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RootCertificateAuthoritiesConfig':
        """Initialize a RootCertificateAuthoritiesConfig object from a json dictionary."""
        args = {}
        if 'root_certificate_authorities' in _dict:
            args['root_certificate_authorities'] = [RootCertificateAuthoritiesConfigItem.from_dict(v) for v in
                                                    _dict.get('root_certificate_authorities')]
        else:
            raise ValueError(
                'Required property \'root_certificate_authorities\' not present in RootCertificateAuthoritiesConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RootCertificateAuthoritiesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'root_certificate_authorities') and self.root_certificate_authorities is not None:
            root_certificate_authorities_list = []
            for v in self.root_certificate_authorities:
                if isinstance(v, dict):
                    root_certificate_authorities_list.append(v)
                else:
                    root_certificate_authorities_list.append(v.to_dict())
            _dict['root_certificate_authorities'] = root_certificate_authorities_list
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RootCertificateAuthoritiesConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RootCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RootCertificateAuthoritiesConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RootCertificateAuthorityConfig(ConfigElementDefConfig):
    """
    Root certificate authority configuration.

    :attr object max_ttl: The maximum time-to-live (TTL) for certificates that are
          created by this CA.
          The value can be supplied as a string representation of a duration in hours, for
          example '8760h'. In the API response, this value is returned in seconds
          (integer).
          Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
    :attr object crl_expiry: (optional) The time until the certificate revocation
          list (CRL) expires.
          The value can be supplied as a string representation of a duration in hours,
          such as `48h`. The default is 72 hours. In the API response, this value is
          returned in seconds (integer).
          **Note:** The CRL is rotated automatically before it expires.
    :attr bool crl_disable: (optional) Disables or enables certificate revocation
          list (CRL) building.
          If CRL building is disabled, a signed but zero-length CRL is returned when
          downloading the CRL. If CRL building is enabled,  it will rebuild the CRL.
    :attr bool crl_distribution_points_encoded: (optional) Determines whether to
          encode the certificate revocation list (CRL) distribution points in the
          certificates that are issued by this certificate authority.
    :attr bool issuing_certificates_urls_encoded: (optional) Determines whether to
          encode the URL of the issuing certificate in the certificates that are issued by
          this certificate authority.
    :attr str common_name: The fully qualified domain name or host domain name for
          the certificate.
    :attr str status: (optional) The status of the certificate authority. The status
          of a root certificate authority is either `configured` or `expired`. For
          intermediate certificate authorities, possible statuses include
          `signing_required`,
          `signed_certificate_required`, `certificate_template_required`, `configured`,
          `expired` or `revoked`.
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to this CA
          certificate.
          The value can be supplied as a string representation of a duration, such as
          `12h`. The value can be supplied in seconds (suffix `s`), minutes (suffix `m`),
          hours (suffix `h`) or days (suffix `d`). The value can't exceed the `max_ttl`
          that is defined in the associated certificate template. In the API response,
          this value is returned in seconds (integer).
    :attr str format: (optional) The format of the returned data.
    :attr str private_key_format: (optional) The format of the generated private
          key.
    :attr str key_type: (optional) The type of private key to generate.
    :attr int key_bits: (optional) The number of bits to use when generating the
          private key.
          Allowable values for RSA keys are: `2048` and `4096`. Allowable values for EC
          keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is `2048`.
          The default for EC keys is `256`.
    :attr int max_path_length: (optional) The maximum path length to encode in the
          generated certificate. `-1` means no limit.
          If the signing certificate has a maximum path length set, the path length is set
          to one less than that of the signing certificate. A limit of `0` means a literal
          path length of zero.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] permitted_dns_domains: (optional) The allowed DNS domains or
          subdomains for the certificates to be signed and issued by this CA certificate.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr dict data: (optional) The data that is associated with the root
          certificate authority. The data object contains the following fields:
          - `certificate`: The root certificate content.
          - `issuing_ca`: The certificate of the certificate authority that signed and
          issued this certificate.
          - `serial_number`: The unique serial number of the root certificate.
    """

    def __init__(self,
                 max_ttl: object,
                 common_name: str,
                 *,
                 crl_expiry: object = None,
                 crl_disable: bool = None,
                 crl_distribution_points_encoded: bool = None,
                 issuing_certificates_urls_encoded: bool = None,
                 status: str = None,
                 expiration_date: datetime = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 private_key_format: str = None,
                 key_type: str = None,
                 key_bits: int = None,
                 max_path_length: int = None,
                 exclude_cn_from_sans: bool = None,
                 permitted_dns_domains: List[str] = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None,
                 data: dict = None) -> None:
        """
        Initialize a RootCertificateAuthorityConfig object.

        :param object max_ttl: The maximum time-to-live (TTL) for certificates that
               are created by this CA.
               The value can be supplied as a string representation of a duration in
               hours, for example '8760h'. In the API response, this value is returned in
               seconds (integer).
               Minimum value is one hour (`1h`). Maximum value is 100 years (`876000h`).
        :param str common_name: The fully qualified domain name or host domain name
               for the certificate.
        :param object crl_expiry: (optional) The time until the certificate
               revocation list (CRL) expires.
               The value can be supplied as a string representation of a duration in
               hours, such as `48h`. The default is 72 hours. In the API response, this
               value is returned in seconds (integer).
               **Note:** The CRL is rotated automatically before it expires.
        :param bool crl_disable: (optional) Disables or enables certificate
               revocation list (CRL) building.
               If CRL building is disabled, a signed but zero-length CRL is returned when
               downloading the CRL. If CRL building is enabled,  it will rebuild the CRL.
        :param bool crl_distribution_points_encoded: (optional) Determines whether
               to encode the certificate revocation list (CRL) distribution points in the
               certificates that are issued by this certificate authority.
        :param bool issuing_certificates_urls_encoded: (optional) Determines
               whether to encode the URL of the issuing certificate in the certificates
               that are issued by this certificate authority.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to this CA
               certificate.
               The value can be supplied as a string representation of a duration, such as
               `12h`. The value can be supplied in seconds (suffix `s`), minutes (suffix
               `m`), hours (suffix `h`) or days (suffix `d`). The value can't exceed the
               `max_ttl` that is defined in the associated certificate template. In the
               API response, this value is returned in seconds (integer).
        :param str format: (optional) The format of the returned data.
        :param str private_key_format: (optional) The format of the generated
               private key.
        :param str key_type: (optional) The type of private key to generate.
        :param int key_bits: (optional) The number of bits to use when generating
               the private key.
               Allowable values for RSA keys are: `2048` and `4096`. Allowable values for
               EC keys are: `224`, `256`, `384`, and `521`. The default for RSA keys is
               `2048`. The default for EC keys is `256`.
        :param int max_path_length: (optional) The maximum path length to encode in
               the generated certificate. `-1` means no limit.
               If the signing certificate has a maximum path length set, the path length
               is set to one less than that of the signing certificate. A limit of `0`
               means a literal path length of zero.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] permitted_dns_domains: (optional) The allowed DNS domains
               or subdomains for the certificates to be signed and issued by this CA
               certificate.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.max_ttl = max_ttl
        self.crl_expiry = crl_expiry
        self.crl_disable = crl_disable
        self.crl_distribution_points_encoded = crl_distribution_points_encoded
        self.issuing_certificates_urls_encoded = issuing_certificates_urls_encoded
        self.common_name = common_name
        self.status = status
        self.expiration_date = expiration_date
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.private_key_format = private_key_format
        self.key_type = key_type
        self.key_bits = key_bits
        self.max_path_length = max_path_length
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.permitted_dns_domains = permitted_dns_domains
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.data = data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RootCertificateAuthorityConfig':
        """Initialize a RootCertificateAuthorityConfig object from a json dictionary."""
        args = {}
        if 'max_ttl' in _dict:
            args['max_ttl'] = _dict.get('max_ttl')
        else:
            raise ValueError('Required property \'max_ttl\' not present in RootCertificateAuthorityConfig JSON')
        if 'crl_expiry' in _dict:
            args['crl_expiry'] = _dict.get('crl_expiry')
        if 'crl_disable' in _dict:
            args['crl_disable'] = _dict.get('crl_disable')
        if 'crl_distribution_points_encoded' in _dict:
            args['crl_distribution_points_encoded'] = _dict.get('crl_distribution_points_encoded')
        if 'issuing_certificates_urls_encoded' in _dict:
            args['issuing_certificates_urls_encoded'] = _dict.get('issuing_certificates_urls_encoded')
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        else:
            raise ValueError('Required property \'common_name\' not present in RootCertificateAuthorityConfig JSON')
        if 'status' in _dict:
            args['status'] = _dict.get('status')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'private_key_format' in _dict:
            args['private_key_format'] = _dict.get('private_key_format')
        if 'key_type' in _dict:
            args['key_type'] = _dict.get('key_type')
        if 'key_bits' in _dict:
            args['key_bits'] = _dict.get('key_bits')
        if 'max_path_length' in _dict:
            args['max_path_length'] = _dict.get('max_path_length')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'permitted_dns_domains' in _dict:
            args['permitted_dns_domains'] = _dict.get('permitted_dns_domains')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'data' in _dict:
            args['data'] = _dict.get('data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RootCertificateAuthorityConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'max_ttl') and self.max_ttl is not None:
            _dict['max_ttl'] = self.max_ttl
        if hasattr(self, 'crl_expiry') and self.crl_expiry is not None:
            _dict['crl_expiry'] = self.crl_expiry
        if hasattr(self, 'crl_disable') and self.crl_disable is not None:
            _dict['crl_disable'] = self.crl_disable
        if hasattr(self, 'crl_distribution_points_encoded') and self.crl_distribution_points_encoded is not None:
            _dict['crl_distribution_points_encoded'] = self.crl_distribution_points_encoded
        if hasattr(self, 'issuing_certificates_urls_encoded') and self.issuing_certificates_urls_encoded is not None:
            _dict['issuing_certificates_urls_encoded'] = self.issuing_certificates_urls_encoded
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'status') and getattr(self, 'status') is not None:
            _dict['status'] = getattr(self, 'status')
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'private_key_format') and self.private_key_format is not None:
            _dict['private_key_format'] = self.private_key_format
        if hasattr(self, 'key_type') and self.key_type is not None:
            _dict['key_type'] = self.key_type
        if hasattr(self, 'key_bits') and self.key_bits is not None:
            _dict['key_bits'] = self.key_bits
        if hasattr(self, 'max_path_length') and self.max_path_length is not None:
            _dict['max_path_length'] = self.max_path_length
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'permitted_dns_domains') and self.permitted_dns_domains is not None:
            _dict['permitted_dns_domains'] = self.permitted_dns_domains
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'data') and getattr(self, 'data') is not None:
            _dict['data'] = getattr(self, 'data')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RootCertificateAuthorityConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RootCertificateAuthorityConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RootCertificateAuthorityConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class StatusEnum(str, Enum):
        """
        The status of the certificate authority. The status of a root certificate
        authority is either `configured` or `expired`. For intermediate certificate
        authorities, possible statuses include `signing_required`,
        `signed_certificate_required`, `certificate_template_required`, `configured`,
        `expired` or `revoked`.
        """
        SIGNING_REQUIRED = 'signing_required'
        SIGNED_CERTIFICATE_REQUIRED = 'signed_certificate_required'
        CERTIFICATE_TEMPLATE_REQUIRED = 'certificate_template_required'
        CONFIGURED = 'configured'
        EXPIRED = 'expired'
        REVOKED = 'revoked'

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'

    class PrivateKeyFormatEnum(str, Enum):
        """
        The format of the generated private key.
        """
        DER = 'der'
        PKCS8 = 'pkcs8'

    class KeyTypeEnum(str, Enum):
        """
        The type of private key to generate.
        """
        RSA = 'rsa'
        EC = 'ec'


class RotateArbitrarySecretBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr str payload: The new secret data to assign to an `arbitrary` secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 payload: str,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotateArbitrarySecretBody object.

        :param str payload: The new secret data to assign to an `arbitrary` secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.payload = payload
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateArbitrarySecretBody':
        """Initialize a RotateArbitrarySecretBody object from a json dictionary."""
        args = {}
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        else:
            raise ValueError('Required property \'payload\' not present in RotateArbitrarySecretBody JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotateArbitrarySecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'payload') and self.payload is not None:
            _dict['payload'] = self.payload
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotateArbitrarySecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotateArbitrarySecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotateArbitrarySecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotateCertificateBody(SecretAction):
    """
    The request body of a rotate certificate action.

    :attr str certificate: The new data to associate with the certificate.
    :attr str private_key: (optional) The new private key to associate with the
          certificate.
    :attr str intermediate: (optional) The new intermediate certificate to associate
          with the certificate.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 certificate: str,
                 *,
                 private_key: str = None,
                 intermediate: str = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotateCertificateBody object.

        :param str certificate: The new data to associate with the certificate.
        :param str private_key: (optional) The new private key to associate with
               the certificate.
        :param str intermediate: (optional) The new intermediate certificate to
               associate with the certificate.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.certificate = certificate
        self.private_key = private_key
        self.intermediate = intermediate
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateCertificateBody':
        """Initialize a RotateCertificateBody object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        else:
            raise ValueError('Required property \'certificate\' not present in RotateCertificateBody JSON')
        if 'private_key' in _dict:
            args['private_key'] = _dict.get('private_key')
        if 'intermediate' in _dict:
            args['intermediate'] = _dict.get('intermediate')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotateCertificateBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        if hasattr(self, 'private_key') and self.private_key is not None:
            _dict['private_key'] = self.private_key
        if hasattr(self, 'intermediate') and self.intermediate is not None:
            _dict['intermediate'] = self.intermediate
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotateCertificateBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotateCertificateBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotateCertificateBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotateCrlActionResult(ConfigElementActionResultConfig):
    """
    Properties that are returned with a successful `rotate_crl` action.

    """

    def __init__(self) -> None:
        """
        Initialize a RotateCrlActionResult object.

        """
        # pylint: disable=super-init-not-called

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateCrlActionResult':
        """Initialize a RotateCrlActionResult object from a json dictionary."""
        return cls(**_dict)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotateCrlActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        return vars(self)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotateCrlActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotateCrlActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotateCrlActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotateKvSecretBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr dict payload: The new secret data to assign to a key-value secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 payload: dict,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotateKvSecretBody object.

        :param dict payload: The new secret data to assign to a key-value secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.payload = payload
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateKvSecretBody':
        """Initialize a RotateKvSecretBody object from a json dictionary."""
        args = {}
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        else:
            raise ValueError('Required property \'payload\' not present in RotateKvSecretBody JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotateKvSecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'payload') and self.payload is not None:
            _dict['payload'] = self.payload
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotateKvSecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotateKvSecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotateKvSecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotatePrivateCertBody(SecretAction):
    """
    The request body of a rotate private certificate action.

    :attr dict custom_metadata: The secret metadata that a user can customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 custom_metadata: dict,
                 *,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotatePrivateCertBody object.

        :param dict custom_metadata: The secret metadata that a user can customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotatePrivateCertBody':
        """Initialize a RotatePrivateCertBody object from a json dictionary."""
        args = {}
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        else:
            raise ValueError('Required property \'custom_metadata\' not present in RotatePrivateCertBody JSON')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotatePrivateCertBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotatePrivateCertBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotatePrivateCertBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotatePrivateCertBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RotatePrivateCertBodyWithCsr(SecretAction):
    """
    The body of a request to rotate a private certificate.

    :attr str csr: The certificate signing request. If you provide a CSR, it is used
          for auto rotation and manual rotation requests that do not include a CSR. If you
          don't include the CSR, the certificate is generated with the last CSR that you
          provided to create the private certificate, or on a previous request to rotate
          the certificate. If no CSR was provided in the past, the certificate is
          generated with a CSR that is created internally.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 csr: str,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotatePrivateCertBodyWithCsr object.

        :param str csr: The certificate signing request. If you provide a CSR, it
               is used for auto rotation and manual rotation requests that do not include
               a CSR. If you don't include the CSR, the certificate is generated with the
               last CSR that you provided to create the private certificate, or on a
               previous request to rotate the certificate. If no CSR was provided in the
               past, the certificate is generated with a CSR that is created internally.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.csr = csr
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotatePrivateCertBodyWithCsr':
        """Initialize a RotatePrivateCertBodyWithCsr object from a json dictionary."""
        args = {}
        if 'csr' in _dict:
            args['csr'] = _dict.get('csr')
        else:
            raise ValueError('Required property \'csr\' not present in RotatePrivateCertBodyWithCsr JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotatePrivateCertBodyWithCsr object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'csr') and self.csr is not None:
            _dict['csr'] = self.csr
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotatePrivateCertBodyWithCsr object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotatePrivateCertBodyWithCsr') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotatePrivateCertBodyWithCsr') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotatePrivateCertBodyWithVersionCustomMetadata(SecretAction):
    """
    The request body of a rotate private certificate action.

    :attr dict version_custom_metadata: The secret version metadata that a user can
          customize.
    """

    def __init__(self,
                 version_custom_metadata: dict) -> None:
        """
        Initialize a RotatePrivateCertBodyWithVersionCustomMetadata object.

        :param dict version_custom_metadata: The secret version metadata that a
               user can customize.
        """
        # pylint: disable=super-init-not-called
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotatePrivateCertBodyWithVersionCustomMetadata':
        """Initialize a RotatePrivateCertBodyWithVersionCustomMetadata object from a json dictionary."""
        args = {}
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        else:
            raise ValueError(
                'Required property \'version_custom_metadata\' not present in RotatePrivateCertBodyWithVersionCustomMetadata JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotatePrivateCertBodyWithVersionCustomMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotatePrivateCertBodyWithVersionCustomMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotatePrivateCertBodyWithVersionCustomMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotatePrivateCertBodyWithVersionCustomMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotatePublicCertBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr bool rotate_keys: Determine whether keys must be rotated.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 rotate_keys: bool,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotatePublicCertBody object.

        :param bool rotate_keys: Determine whether keys must be rotated.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.rotate_keys = rotate_keys
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotatePublicCertBody':
        """Initialize a RotatePublicCertBody object from a json dictionary."""
        args = {}
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
        else:
            raise ValueError('Required property \'rotate_keys\' not present in RotatePublicCertBody JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotatePublicCertBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'rotate_keys') and self.rotate_keys is not None:
            _dict['rotate_keys'] = self.rotate_keys
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotatePublicCertBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotatePublicCertBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotatePublicCertBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class RotateUsernamePasswordSecretBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr str password: The new password to assign to a `username_password` secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    """

    def __init__(self,
                 password: str,
                 *,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None) -> None:
        """
        Initialize a RotateUsernamePasswordSecretBody object.

        :param str password: The new password to assign to a `username_password`
               secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        """
        # pylint: disable=super-init-not-called
        self.password = password
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateUsernamePasswordSecretBody':
        """Initialize a RotateUsernamePasswordSecretBody object from a json dictionary."""
        args = {}
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        else:
            raise ValueError('Required property \'password\' not present in RotateUsernamePasswordSecretBody JSON')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RotateUsernamePasswordSecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this RotateUsernamePasswordSecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'RotateUsernamePasswordSecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'RotateUsernamePasswordSecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SecretPolicyRotationRotationPolicyRotation(SecretPolicyRotationRotation):
    """
    The secret rotation time interval.

    :attr int interval: The length of the secret rotation time interval.
    :attr str unit: The units for the secret rotation time interval.
    """

    def __init__(self,
                 interval: int,
                 unit: str) -> None:
        """
        Initialize a SecretPolicyRotationRotationPolicyRotation object.

        :param int interval: The length of the secret rotation time interval.
        :param str unit: The units for the secret rotation time interval.
        """
        # pylint: disable=super-init-not-called
        self.interval = interval
        self.unit = unit

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretPolicyRotationRotationPolicyRotation':
        """Initialize a SecretPolicyRotationRotationPolicyRotation object from a json dictionary."""
        args = {}
        if 'interval' in _dict:
            args['interval'] = _dict.get('interval')
        else:
            raise ValueError(
                'Required property \'interval\' not present in SecretPolicyRotationRotationPolicyRotation JSON')
        if 'unit' in _dict:
            args['unit'] = _dict.get('unit')
        else:
            raise ValueError(
                'Required property \'unit\' not present in SecretPolicyRotationRotationPolicyRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretPolicyRotationRotationPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'interval') and self.interval is not None:
            _dict['interval'] = self.interval
        if hasattr(self, 'unit') and self.unit is not None:
            _dict['unit'] = self.unit
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretPolicyRotationRotationPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretPolicyRotationRotationPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretPolicyRotationRotationPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class UnitEnum(str, Enum):
        """
        The units for the secret rotation time interval.
        """
        DAY = 'day'
        MONTH = 'month'


class SecretPolicyRotationRotationPublicCertPolicyRotation(SecretPolicyRotationRotation):
    """
    The `public_cert` secret rotation policy.

    :attr bool auto_rotate:
    :attr bool rotate_keys:
    """

    def __init__(self,
                 auto_rotate: bool,
                 rotate_keys: bool) -> None:
        """
        Initialize a SecretPolicyRotationRotationPublicCertPolicyRotation object.

        :param bool auto_rotate:
        :param bool rotate_keys:
        """
        # pylint: disable=super-init-not-called
        self.auto_rotate = auto_rotate
        self.rotate_keys = rotate_keys

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretPolicyRotationRotationPublicCertPolicyRotation':
        """Initialize a SecretPolicyRotationRotationPublicCertPolicyRotation object from a json dictionary."""
        args = {}
        if 'auto_rotate' in _dict:
            args['auto_rotate'] = _dict.get('auto_rotate')
        else:
            raise ValueError(
                'Required property \'auto_rotate\' not present in SecretPolicyRotationRotationPublicCertPolicyRotation JSON')
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
        else:
            raise ValueError(
                'Required property \'rotate_keys\' not present in SecretPolicyRotationRotationPublicCertPolicyRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretPolicyRotationRotationPublicCertPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'auto_rotate') and self.auto_rotate is not None:
            _dict['auto_rotate'] = self.auto_rotate
        if hasattr(self, 'rotate_keys') and self.rotate_keys is not None:
            _dict['rotate_keys'] = self.rotate_keys
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretPolicyRotationRotationPublicCertPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretPolicyRotationRotationPublicCertPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretPolicyRotationRotationPublicCertPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SetSignedAction(ConfigAction):
    """
    A request to set a signed certificate in an intermediate certificate authority.

    :attr str certificate: The PEM-encoded certificate.
    """

    def __init__(self,
                 certificate: str) -> None:
        """
        Initialize a SetSignedAction object.

        :param str certificate: The PEM-encoded certificate.
        """
        # pylint: disable=super-init-not-called
        self.certificate = certificate

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SetSignedAction':
        """Initialize a SetSignedAction object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        else:
            raise ValueError('Required property \'certificate\' not present in SetSignedAction JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetSignedAction object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate') and self.certificate is not None:
            _dict['certificate'] = self.certificate
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetSignedAction object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SetSignedAction') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SetSignedAction') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SetSignedActionResult(ConfigElementActionResultConfig):
    """
    Properties that are returned with a successful `set_signed` action.

    """

    def __init__(self) -> None:
        """
        Initialize a SetSignedActionResult object.

        """
        # pylint: disable=super-init-not-called

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SetSignedActionResult':
        """Initialize a SetSignedActionResult object from a json dictionary."""
        return cls(**_dict)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SetSignedActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        return vars(self)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SetSignedActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SetSignedActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SetSignedActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class SignCsrAction(ConfigAction):
    """
    A request to sign a certificate signing request (CSR).

    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration in hours,
          such as `12h`. The value can't exceed the `max_ttl` that is defined in the
          associated certificate template.
    :attr str format: (optional) The format of the returned data.
    :attr int max_path_length: (optional) The maximum path length to encode in the
          generated certificate. `-1` means no limit.
          If the signing certificate has a maximum path length set, the path length is set
          to one less than that of the signing certificate. A limit of `0` means a literal
          path length of zero.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] permitted_dns_domains: (optional) The allowed DNS domains or
          subdomains for the certificates to be signed and issued by this CA certificate.
    :attr bool use_csr_values: (optional) Determines whether to use values from a
          certificate signing request (CSR) to complete a `sign_csr` action. If set to
          `true`, then:
          1) Subject information, including names and alternate names, are preserved from
          the CSR rather than using the values provided in the other parameters to this
          operation.
          2) Any key usages (for example, non-repudiation) that are requested in the CSR
          are added to the basic set of key usages used for CA certs signed by this
          intermediate authority.
          3) Extensions that are requested in the CSR are copied into the issued private
          certificate.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr str csr: The PEM-encoded certificate signing request (CSR). This field is
          required for the `sign_csr` action.
    """

    def __init__(self,
                 csr: str,
                 *,
                 common_name: str = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 max_path_length: int = None,
                 exclude_cn_from_sans: bool = None,
                 permitted_dns_domains: List[str] = None,
                 use_csr_values: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None) -> None:
        """
        Initialize a SignCsrAction object.

        :param str csr: The PEM-encoded certificate signing request (CSR). This
               field is required for the `sign_csr` action.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration in
               hours, such as `12h`. The value can't exceed the `max_ttl` that is defined
               in the associated certificate template.
        :param str format: (optional) The format of the returned data.
        :param int max_path_length: (optional) The maximum path length to encode in
               the generated certificate. `-1` means no limit.
               If the signing certificate has a maximum path length set, the path length
               is set to one less than that of the signing certificate. A limit of `0`
               means a literal path length of zero.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] permitted_dns_domains: (optional) The allowed DNS domains
               or subdomains for the certificates to be signed and issued by this CA
               certificate.
        :param bool use_csr_values: (optional) Determines whether to use values
               from a certificate signing request (CSR) to complete a `sign_csr` action.
               If set to `true`, then:
               1) Subject information, including names and alternate names, are preserved
               from the CSR rather than using the values provided in the other parameters
               to this operation.
               2) Any key usages (for example, non-repudiation) that are requested in the
               CSR are added to the basic set of key usages used for CA certs signed by
               this intermediate authority.
               3) Extensions that are requested in the CSR are copied into the issued
               private certificate.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.common_name = common_name
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.max_path_length = max_path_length
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.permitted_dns_domains = permitted_dns_domains
        self.use_csr_values = use_csr_values
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.csr = csr

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignCsrAction':
        """Initialize a SignCsrAction object from a json dictionary."""
        args = {}
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'max_path_length' in _dict:
            args['max_path_length'] = _dict.get('max_path_length')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'permitted_dns_domains' in _dict:
            args['permitted_dns_domains'] = _dict.get('permitted_dns_domains')
        if 'use_csr_values' in _dict:
            args['use_csr_values'] = _dict.get('use_csr_values')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'csr' in _dict:
            args['csr'] = _dict.get('csr')
        else:
            raise ValueError('Required property \'csr\' not present in SignCsrAction JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignCsrAction object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'max_path_length') and self.max_path_length is not None:
            _dict['max_path_length'] = self.max_path_length
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'permitted_dns_domains') and self.permitted_dns_domains is not None:
            _dict['permitted_dns_domains'] = self.permitted_dns_domains
        if hasattr(self, 'use_csr_values') and self.use_csr_values is not None:
            _dict['use_csr_values'] = self.use_csr_values
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'csr') and self.csr is not None:
            _dict['csr'] = self.csr
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignCsrAction object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignCsrAction') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignCsrAction') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'


class SignCsrActionResult(ConfigElementActionResultConfig):
    """
    Properties that are returned with a successful `sign_csr` action.

    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration in hours,
          such as `12h`. The value can't exceed the `max_ttl` that is defined in the
          associated certificate template.
    :attr str format: (optional) The format of the returned data.
    :attr int max_path_length: (optional) The maximum path length to encode in the
          generated certificate. `-1` means no limit.
          If the signing certificate has a maximum path length set, the path length is set
          to one less than that of the signing certificate. A limit of `0` means a literal
          path length of zero.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] permitted_dns_domains: (optional) The allowed DNS domains or
          subdomains for the certificates to be signed and issued by this CA certificate.
    :attr bool use_csr_values: (optional) Determines whether to use values from a
          certificate signing request (CSR) to complete a `sign_csr` action. If set to
          `true`, then:
          1) Subject information, including names and alternate names, are preserved from
          the CSR rather than using the values provided in the other parameters to this
          operation.
          2) Any key usages (for example, non-repudiation) that are requested in the CSR
          are added to the basic set of key usages used for CA certs signed by this
          intermediate authority.
          3) Extensions that are requested in the CSR are copied into the issued private
          certificate.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr SignActionResultData data: (optional) Properties that are returned with a
          successful `sign` action.
    :attr str csr: The PEM-encoded certificate signing request (CSR).
    """

    def __init__(self,
                 csr: str,
                 *,
                 common_name: str = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 max_path_length: int = None,
                 exclude_cn_from_sans: bool = None,
                 permitted_dns_domains: List[str] = None,
                 use_csr_values: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None,
                 data: 'SignActionResultData' = None) -> None:
        """
        Initialize a SignCsrActionResult object.

        :param str csr: The PEM-encoded certificate signing request (CSR).
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration in
               hours, such as `12h`. The value can't exceed the `max_ttl` that is defined
               in the associated certificate template.
        :param str format: (optional) The format of the returned data.
        :param int max_path_length: (optional) The maximum path length to encode in
               the generated certificate. `-1` means no limit.
               If the signing certificate has a maximum path length set, the path length
               is set to one less than that of the signing certificate. A limit of `0`
               means a literal path length of zero.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] permitted_dns_domains: (optional) The allowed DNS domains
               or subdomains for the certificates to be signed and issued by this CA
               certificate.
        :param bool use_csr_values: (optional) Determines whether to use values
               from a certificate signing request (CSR) to complete a `sign_csr` action.
               If set to `true`, then:
               1) Subject information, including names and alternate names, are preserved
               from the CSR rather than using the values provided in the other parameters
               to this operation.
               2) Any key usages (for example, non-repudiation) that are requested in the
               CSR are added to the basic set of key usages used for CA certs signed by
               this intermediate authority.
               3) Extensions that are requested in the CSR are copied into the issued
               private certificate.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.common_name = common_name
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.max_path_length = max_path_length
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.permitted_dns_domains = permitted_dns_domains
        self.use_csr_values = use_csr_values
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.data = data
        self.csr = csr

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignCsrActionResult':
        """Initialize a SignCsrActionResult object from a json dictionary."""
        args = {}
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'max_path_length' in _dict:
            args['max_path_length'] = _dict.get('max_path_length')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'permitted_dns_domains' in _dict:
            args['permitted_dns_domains'] = _dict.get('permitted_dns_domains')
        if 'use_csr_values' in _dict:
            args['use_csr_values'] = _dict.get('use_csr_values')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'data' in _dict:
            args['data'] = SignActionResultData.from_dict(_dict.get('data'))
        if 'csr' in _dict:
            args['csr'] = _dict.get('csr')
        else:
            raise ValueError('Required property \'csr\' not present in SignCsrActionResult JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignCsrActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'max_path_length') and self.max_path_length is not None:
            _dict['max_path_length'] = self.max_path_length
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'permitted_dns_domains') and self.permitted_dns_domains is not None:
            _dict['permitted_dns_domains'] = self.permitted_dns_domains
        if hasattr(self, 'use_csr_values') and self.use_csr_values is not None:
            _dict['use_csr_values'] = self.use_csr_values
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'data') and getattr(self, 'data') is not None:
            if isinstance(getattr(self, 'data'), dict):
                _dict['data'] = getattr(self, 'data')
            else:
                _dict['data'] = getattr(self, 'data').to_dict()
        if hasattr(self, 'csr') and self.csr is not None:
            _dict['csr'] = self.csr
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignCsrActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignCsrActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignCsrActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'


class SignIntermediateAction(ConfigAction):
    """
    A request to sign an intermediate certificate authority.

    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration in hours,
          such as `12h`. The value can't exceed the `max_ttl` that is defined in the
          associated certificate template.
    :attr str format: (optional) The format of the returned data.
    :attr int max_path_length: (optional) The maximum path length to encode in the
          generated certificate. `-1` means no limit.
          If the signing certificate has a maximum path length set, the path length is set
          to one less than that of the signing certificate. A limit of `0` means a literal
          path length of zero.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] permitted_dns_domains: (optional) The allowed DNS domains or
          subdomains for the certificates to be signed and issued by this CA certificate.
    :attr bool use_csr_values: (optional) Determines whether to use values from a
          certificate signing request (CSR) to complete a `sign_csr` action. If set to
          `true`, then:
          1) Subject information, including names and alternate names, are preserved from
          the CSR rather than using the values provided in the other parameters to this
          operation.
          2) Any key usages (for example, non-repudiation) that are requested in the CSR
          are added to the basic set of key usages used for CA certs signed by this
          intermediate authority.
          3) Extensions that are requested in the CSR are copied into the issued private
          certificate.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr str intermediate_certificate_authority: The intermediate certificate
          authority to be signed. The name must match one of the pre-configured
          intermediate certificate authorities.
    """

    def __init__(self,
                 intermediate_certificate_authority: str,
                 *,
                 common_name: str = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 max_path_length: int = None,
                 exclude_cn_from_sans: bool = None,
                 permitted_dns_domains: List[str] = None,
                 use_csr_values: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None) -> None:
        """
        Initialize a SignIntermediateAction object.

        :param str intermediate_certificate_authority: The intermediate certificate
               authority to be signed. The name must match one of the pre-configured
               intermediate certificate authorities.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration in
               hours, such as `12h`. The value can't exceed the `max_ttl` that is defined
               in the associated certificate template.
        :param str format: (optional) The format of the returned data.
        :param int max_path_length: (optional) The maximum path length to encode in
               the generated certificate. `-1` means no limit.
               If the signing certificate has a maximum path length set, the path length
               is set to one less than that of the signing certificate. A limit of `0`
               means a literal path length of zero.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] permitted_dns_domains: (optional) The allowed DNS domains
               or subdomains for the certificates to be signed and issued by this CA
               certificate.
        :param bool use_csr_values: (optional) Determines whether to use values
               from a certificate signing request (CSR) to complete a `sign_csr` action.
               If set to `true`, then:
               1) Subject information, including names and alternate names, are preserved
               from the CSR rather than using the values provided in the other parameters
               to this operation.
               2) Any key usages (for example, non-repudiation) that are requested in the
               CSR are added to the basic set of key usages used for CA certs signed by
               this intermediate authority.
               3) Extensions that are requested in the CSR are copied into the issued
               private certificate.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.common_name = common_name
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.max_path_length = max_path_length
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.permitted_dns_domains = permitted_dns_domains
        self.use_csr_values = use_csr_values
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.intermediate_certificate_authority = intermediate_certificate_authority

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignIntermediateAction':
        """Initialize a SignIntermediateAction object from a json dictionary."""
        args = {}
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'max_path_length' in _dict:
            args['max_path_length'] = _dict.get('max_path_length')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'permitted_dns_domains' in _dict:
            args['permitted_dns_domains'] = _dict.get('permitted_dns_domains')
        if 'use_csr_values' in _dict:
            args['use_csr_values'] = _dict.get('use_csr_values')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'intermediate_certificate_authority' in _dict:
            args['intermediate_certificate_authority'] = _dict.get('intermediate_certificate_authority')
        else:
            raise ValueError(
                'Required property \'intermediate_certificate_authority\' not present in SignIntermediateAction JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignIntermediateAction object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'max_path_length') and self.max_path_length is not None:
            _dict['max_path_length'] = self.max_path_length
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'permitted_dns_domains') and self.permitted_dns_domains is not None:
            _dict['permitted_dns_domains'] = self.permitted_dns_domains
        if hasattr(self, 'use_csr_values') and self.use_csr_values is not None:
            _dict['use_csr_values'] = self.use_csr_values
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'intermediate_certificate_authority') and self.intermediate_certificate_authority is not None:
            _dict['intermediate_certificate_authority'] = self.intermediate_certificate_authority
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignIntermediateAction object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignIntermediateAction') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignIntermediateAction') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'


class SignIntermediateActionResult(ConfigElementActionResultConfig):
    """
    Properties that are returned with a successful `sign_intermediate` action.

    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr str alt_names: (optional) The Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
          The alternative names can be host names or email addresses.
    :attr str ip_sans: (optional) The IP Subject Alternative Names to define for the
          CA certificate, in a comma-delimited list.
    :attr str uri_sans: (optional) The URI Subject Alternative Names to define for
          the CA certificate, in a comma-delimited list.
    :attr List[str] other_sans: (optional) The custom Object Identifier (OID) or
          UTF8-string Subject Alternative Names to define for the CA certificate.
          The alternative names must match the values that are specified in the
          `allowed_other_sans` field in the associated certificate template. The format is
          the same as OpenSSL: `<oid>:<type>:<value>` where the current valid type is
          `UTF8`.
    :attr object ttl: (optional) The time-to-live (TTL) to assign to a private
          certificate.
          The value can be supplied as a string representation of a duration in hours,
          such as `12h`. The value can't exceed the `max_ttl` that is defined in the
          associated certificate template.
    :attr str format: (optional) The format of the returned data.
    :attr int max_path_length: (optional) The maximum path length to encode in the
          generated certificate. `-1` means no limit.
          If the signing certificate has a maximum path length set, the path length is set
          to one less than that of the signing certificate. A limit of `0` means a literal
          path length of zero.
    :attr bool exclude_cn_from_sans: (optional) Controls whether the common name is
          excluded from Subject Alternative Names (SANs).
          If set to `true`, the common name is is not included in DNS or Email SANs if
          they apply. This field can be useful if the common name is not a hostname or an
          email address, but is instead a human-readable identifier.
    :attr List[str] permitted_dns_domains: (optional) The allowed DNS domains or
          subdomains for the certificates to be signed and issued by this CA certificate.
    :attr bool use_csr_values: (optional) Determines whether to use values from a
          certificate signing request (CSR) to complete a `sign_csr` action. If set to
          `true`, then:
          1) Subject information, including names and alternate names, are preserved from
          the CSR rather than using the values provided in the other parameters to this
          operation.
          2) Any key usages (for example, non-repudiation) that are requested in the CSR
          are added to the basic set of key usages used for CA certs signed by this
          intermediate authority.
          3) Extensions that are requested in the CSR are copied into the issued private
          certificate.
    :attr List[str] ou: (optional) The Organizational Unit (OU) values to define in
          the subject field of the resulting certificate.
    :attr List[str] organization: (optional) The Organization (O) values to define
          in the subject field of the resulting certificate.
    :attr List[str] country: (optional) The Country (C) values to define in the
          subject field of the resulting certificate.
    :attr List[str] locality: (optional) The Locality (L) values to define in the
          subject field of the resulting certificate.
    :attr List[str] province: (optional) The Province (ST) values to define in the
          subject field of the resulting certificate.
    :attr List[str] street_address: (optional) The Street Address values in the
          subject field of the resulting certificate.
    :attr List[str] postal_code: (optional) The Postal Code values in the subject
          field of the resulting certificate.
    :attr str serial_number: (optional) The serial number to assign to the generated
          certificate. To assign a random serial number, you can omit this field.
    :attr SignIntermediateActionResultData data: (optional) Properties that are
          returned with a successful `sign` action.
    :attr str intermediate_certificate_authority: The signed intermediate
          certificate authority.
    """

    def __init__(self,
                 intermediate_certificate_authority: str,
                 *,
                 common_name: str = None,
                 alt_names: str = None,
                 ip_sans: str = None,
                 uri_sans: str = None,
                 other_sans: List[str] = None,
                 ttl: object = None,
                 format: str = None,
                 max_path_length: int = None,
                 exclude_cn_from_sans: bool = None,
                 permitted_dns_domains: List[str] = None,
                 use_csr_values: bool = None,
                 ou: List[str] = None,
                 organization: List[str] = None,
                 country: List[str] = None,
                 locality: List[str] = None,
                 province: List[str] = None,
                 street_address: List[str] = None,
                 postal_code: List[str] = None,
                 serial_number: str = None,
                 data: 'SignIntermediateActionResultData' = None) -> None:
        """
        Initialize a SignIntermediateActionResult object.

        :param str intermediate_certificate_authority: The signed intermediate
               certificate authority.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param str alt_names: (optional) The Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
               The alternative names can be host names or email addresses.
        :param str ip_sans: (optional) The IP Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param str uri_sans: (optional) The URI Subject Alternative Names to define
               for the CA certificate, in a comma-delimited list.
        :param List[str] other_sans: (optional) The custom Object Identifier (OID)
               or UTF8-string Subject Alternative Names to define for the CA certificate.
               The alternative names must match the values that are specified in the
               `allowed_other_sans` field in the associated certificate template. The
               format is the same as OpenSSL: `<oid>:<type>:<value>` where the current
               valid type is `UTF8`.
        :param object ttl: (optional) The time-to-live (TTL) to assign to a private
               certificate.
               The value can be supplied as a string representation of a duration in
               hours, such as `12h`. The value can't exceed the `max_ttl` that is defined
               in the associated certificate template.
        :param str format: (optional) The format of the returned data.
        :param int max_path_length: (optional) The maximum path length to encode in
               the generated certificate. `-1` means no limit.
               If the signing certificate has a maximum path length set, the path length
               is set to one less than that of the signing certificate. A limit of `0`
               means a literal path length of zero.
        :param bool exclude_cn_from_sans: (optional) Controls whether the common
               name is excluded from Subject Alternative Names (SANs).
               If set to `true`, the common name is is not included in DNS or Email SANs
               if they apply. This field can be useful if the common name is not a
               hostname or an email address, but is instead a human-readable identifier.
        :param List[str] permitted_dns_domains: (optional) The allowed DNS domains
               or subdomains for the certificates to be signed and issued by this CA
               certificate.
        :param bool use_csr_values: (optional) Determines whether to use values
               from a certificate signing request (CSR) to complete a `sign_csr` action.
               If set to `true`, then:
               1) Subject information, including names and alternate names, are preserved
               from the CSR rather than using the values provided in the other parameters
               to this operation.
               2) Any key usages (for example, non-repudiation) that are requested in the
               CSR are added to the basic set of key usages used for CA certs signed by
               this intermediate authority.
               3) Extensions that are requested in the CSR are copied into the issued
               private certificate.
        :param List[str] ou: (optional) The Organizational Unit (OU) values to
               define in the subject field of the resulting certificate.
        :param List[str] organization: (optional) The Organization (O) values to
               define in the subject field of the resulting certificate.
        :param List[str] country: (optional) The Country (C) values to define in
               the subject field of the resulting certificate.
        :param List[str] locality: (optional) The Locality (L) values to define in
               the subject field of the resulting certificate.
        :param List[str] province: (optional) The Province (ST) values to define in
               the subject field of the resulting certificate.
        :param List[str] street_address: (optional) The Street Address values in
               the subject field of the resulting certificate.
        :param List[str] postal_code: (optional) The Postal Code values in the
               subject field of the resulting certificate.
        :param str serial_number: (optional) The serial number to assign to the
               generated certificate. To assign a random serial number, you can omit this
               field.
        """
        # pylint: disable=super-init-not-called
        self.common_name = common_name
        self.alt_names = alt_names
        self.ip_sans = ip_sans
        self.uri_sans = uri_sans
        self.other_sans = other_sans
        self.ttl = ttl
        self.format = format
        self.max_path_length = max_path_length
        self.exclude_cn_from_sans = exclude_cn_from_sans
        self.permitted_dns_domains = permitted_dns_domains
        self.use_csr_values = use_csr_values
        self.ou = ou
        self.organization = organization
        self.country = country
        self.locality = locality
        self.province = province
        self.street_address = street_address
        self.postal_code = postal_code
        self.serial_number = serial_number
        self.data = data
        self.intermediate_certificate_authority = intermediate_certificate_authority

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SignIntermediateActionResult':
        """Initialize a SignIntermediateActionResult object from a json dictionary."""
        args = {}
        if 'common_name' in _dict:
            args['common_name'] = _dict.get('common_name')
        if 'alt_names' in _dict:
            args['alt_names'] = _dict.get('alt_names')
        if 'ip_sans' in _dict:
            args['ip_sans'] = _dict.get('ip_sans')
        if 'uri_sans' in _dict:
            args['uri_sans'] = _dict.get('uri_sans')
        if 'other_sans' in _dict:
            args['other_sans'] = _dict.get('other_sans')
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'format' in _dict:
            args['format'] = _dict.get('format')
        if 'max_path_length' in _dict:
            args['max_path_length'] = _dict.get('max_path_length')
        if 'exclude_cn_from_sans' in _dict:
            args['exclude_cn_from_sans'] = _dict.get('exclude_cn_from_sans')
        if 'permitted_dns_domains' in _dict:
            args['permitted_dns_domains'] = _dict.get('permitted_dns_domains')
        if 'use_csr_values' in _dict:
            args['use_csr_values'] = _dict.get('use_csr_values')
        if 'ou' in _dict:
            args['ou'] = _dict.get('ou')
        if 'organization' in _dict:
            args['organization'] = _dict.get('organization')
        if 'country' in _dict:
            args['country'] = _dict.get('country')
        if 'locality' in _dict:
            args['locality'] = _dict.get('locality')
        if 'province' in _dict:
            args['province'] = _dict.get('province')
        if 'street_address' in _dict:
            args['street_address'] = _dict.get('street_address')
        if 'postal_code' in _dict:
            args['postal_code'] = _dict.get('postal_code')
        if 'serial_number' in _dict:
            args['serial_number'] = _dict.get('serial_number')
        if 'data' in _dict:
            args['data'] = SignIntermediateActionResultData.from_dict(_dict.get('data'))
        if 'intermediate_certificate_authority' in _dict:
            args['intermediate_certificate_authority'] = _dict.get('intermediate_certificate_authority')
        else:
            raise ValueError(
                'Required property \'intermediate_certificate_authority\' not present in SignIntermediateActionResult JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SignIntermediateActionResult object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'common_name') and self.common_name is not None:
            _dict['common_name'] = self.common_name
        if hasattr(self, 'alt_names') and self.alt_names is not None:
            _dict['alt_names'] = self.alt_names
        if hasattr(self, 'ip_sans') and self.ip_sans is not None:
            _dict['ip_sans'] = self.ip_sans
        if hasattr(self, 'uri_sans') and self.uri_sans is not None:
            _dict['uri_sans'] = self.uri_sans
        if hasattr(self, 'other_sans') and self.other_sans is not None:
            _dict['other_sans'] = self.other_sans
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'format') and self.format is not None:
            _dict['format'] = self.format
        if hasattr(self, 'max_path_length') and self.max_path_length is not None:
            _dict['max_path_length'] = self.max_path_length
        if hasattr(self, 'exclude_cn_from_sans') and self.exclude_cn_from_sans is not None:
            _dict['exclude_cn_from_sans'] = self.exclude_cn_from_sans
        if hasattr(self, 'permitted_dns_domains') and self.permitted_dns_domains is not None:
            _dict['permitted_dns_domains'] = self.permitted_dns_domains
        if hasattr(self, 'use_csr_values') and self.use_csr_values is not None:
            _dict['use_csr_values'] = self.use_csr_values
        if hasattr(self, 'ou') and self.ou is not None:
            _dict['ou'] = self.ou
        if hasattr(self, 'organization') and self.organization is not None:
            _dict['organization'] = self.organization
        if hasattr(self, 'country') and self.country is not None:
            _dict['country'] = self.country
        if hasattr(self, 'locality') and self.locality is not None:
            _dict['locality'] = self.locality
        if hasattr(self, 'province') and self.province is not None:
            _dict['province'] = self.province
        if hasattr(self, 'street_address') and self.street_address is not None:
            _dict['street_address'] = self.street_address
        if hasattr(self, 'postal_code') and self.postal_code is not None:
            _dict['postal_code'] = self.postal_code
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'data') and getattr(self, 'data') is not None:
            if isinstance(getattr(self, 'data'), dict):
                _dict['data'] = getattr(self, 'data')
            else:
                _dict['data'] = getattr(self, 'data').to_dict()
        if hasattr(self, 'intermediate_certificate_authority') and self.intermediate_certificate_authority is not None:
            _dict['intermediate_certificate_authority'] = self.intermediate_certificate_authority
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SignIntermediateActionResult object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SignIntermediateActionResult') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SignIntermediateActionResult') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class FormatEnum(str, Enum):
        """
        The format of the returned data.
        """
        PEM = 'pem'
        PEM_BUNDLE = 'pem_bundle'


class UsernamePasswordSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a username_password secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be in the range 2 - 30 characters,
          including spaces. Special characters that are not permitted include the angled
          bracket, comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 labels: List[str] = None,
                 description: str = None,
                 secret_group_id: str = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 expiration_date: datetime = None) -> None:
        """
        Initialize a UsernamePasswordSecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be in the range 2 - 30
               characters, including spaces. Special characters that are not permitted
               include the angled bracket, comma, colon, ampersand, and vertical pipe
               character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.expiration_date = expiration_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretMetadata':
        """Initialize a UsernamePasswordSecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in UsernamePasswordSecretMetadata JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsernamePasswordSecretMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and getattr(self, 'secret_group_id') is not None:
            _dict['secret_group_id'] = getattr(self, 'secret_group_id')
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsernamePasswordSecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsernamePasswordSecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsernamePasswordSecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class UsernamePasswordSecretResource(SecretResource):
    """
    Properties that describe a secret.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str name: A human-readable alias to assign to your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as an alias for your secret.
    :attr str description: (optional) An extended description of your secret.
          To protect your privacy, do not use personal data, such as your name or
          location, as a description for your secret.
    :attr str secret_group_id: (optional) The v4 UUID that uniquely identifies the
          secret group to assign to this secret.
          If you omit this parameter, your secret is assigned to the `default` secret
          group.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be 2 - 30 characters, including
          spaces. Special characters that are not permitted include the angled bracket,
          comma, colon, ampersand, and vertical pipe character (|).
          To protect your privacy, do not use personal data, such as your name or
          location, as a label for your secret.
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr str secret_type: (optional) The secret type.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your Secrets Manager resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when the actual secret is
          modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret.
    :attr dict custom_metadata: (optional) The secret metadata that a user can
          customize.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr str username: (optional) The username to assign to this secret.
    :attr str password: (optional) The password to assign to this secret.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version. The data object contains the following fields:
          - `username`: The username that is associated with the secret version.
          - `password`: The password that is associated with the secret version.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr datetime next_rotation_date: (optional) The date that the secret is
          scheduled for automatic rotation.
          The service automatically creates a new version of the secret on its next
          rotation date. This field exists only for secrets that can be auto-rotated and
          have an existing rotation policy.
    """

    def __init__(self,
                 name: str,
                 *,
                 id: str = None,
                 description: str = None,
                 secret_group_id: str = None,
                 labels: List[str] = None,
                 state: int = None,
                 state_description: str = None,
                 secret_type: str = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 versions_total: int = None,
                 versions: List[dict] = None,
                 locks_total: int = None,
                 custom_metadata: dict = None,
                 version_custom_metadata: dict = None,
                 username: str = None,
                 password: str = None,
                 secret_data: dict = None,
                 expiration_date: datetime = None,
                 next_rotation_date: datetime = None) -> None:
        """
        Initialize a UsernamePasswordSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be 2 - 30 characters, including
               spaces. Special characters that are not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param dict custom_metadata: (optional) The secret metadata that a user can
               customize.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param str username: (optional) The username to assign to this secret.
        :param str password: (optional) The password to assign to this secret.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.labels = labels
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.versions_total = versions_total
        self.versions = versions
        self.locks_total = locks_total
        self.custom_metadata = custom_metadata
        self.version_custom_metadata = version_custom_metadata
        self.username = username
        self.password = password
        self.secret_data = secret_data
        self.expiration_date = expiration_date
        self.next_rotation_date = next_rotation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretResource':
        """Initialize a UsernamePasswordSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in UsernamePasswordSecretResource JSON')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'secret_group_id' in _dict:
            args['secret_group_id'] = _dict.get('secret_group_id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'state' in _dict:
            args['state'] = _dict.get('state')
        if 'state_description' in _dict:
            args['state_description'] = _dict.get('state_description')
        if 'secret_type' in _dict:
            args['secret_type'] = _dict.get('secret_type')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'versions_total' in _dict:
            args['versions_total'] = _dict.get('versions_total')
        if 'versions' in _dict:
            args['versions'] = _dict.get('versions')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'custom_metadata' in _dict:
            args['custom_metadata'] = _dict.get('custom_metadata')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'next_rotation_date' in _dict:
            args['next_rotation_date'] = string_to_datetime(_dict.get('next_rotation_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsernamePasswordSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'name') and self.name is not None:
            _dict['name'] = self.name
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'secret_group_id') and self.secret_group_id is not None:
            _dict['secret_group_id'] = self.secret_group_id
        if hasattr(self, 'labels') and self.labels is not None:
            _dict['labels'] = self.labels
        if hasattr(self, 'state') and getattr(self, 'state') is not None:
            _dict['state'] = getattr(self, 'state')
        if hasattr(self, 'state_description') and getattr(self, 'state_description') is not None:
            _dict['state_description'] = getattr(self, 'state_description')
        if hasattr(self, 'secret_type') and getattr(self, 'secret_type') is not None:
            _dict['secret_type'] = getattr(self, 'secret_type')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'versions_total') and getattr(self, 'versions_total') is not None:
            _dict['versions_total'] = getattr(self, 'versions_total')
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = getattr(self, 'versions')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'custom_metadata') and self.custom_metadata is not None:
            _dict['custom_metadata'] = self.custom_metadata
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        if hasattr(self, 'secret_data') and getattr(self, 'secret_data') is not None:
            _dict['secret_data'] = getattr(self, 'secret_data')
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        if hasattr(self, 'next_rotation_date') and getattr(self, 'next_rotation_date') is not None:
            _dict['next_rotation_date'] = datetime_to_string(getattr(self, 'next_rotation_date'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsernamePasswordSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsernamePasswordSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsernamePasswordSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        PRIVATE_CERT = 'private_cert'
        KV = 'kv'


class UsernamePasswordSecretVersion(SecretVersion):
    """
    UsernamePasswordSecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    :attr dict secret_data: (optional) The data that is associated with the secret
          version. The data object contains the following fields:
          - `username`: The username that is associated with the secret version.
          - `password`: The password that is associated with the secret version.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None,
                 secret_data: dict = None) -> None:
        """
        Initialize a UsernamePasswordSecretVersion object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        :param dict secret_data: (optional) The data that is associated with the
               secret version. The data object contains the following fields:
               - `username`: The username that is associated with the secret version.
               - `password`: The password that is associated with the secret version.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretVersion':
        """Initialize a UsernamePasswordSecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsernamePasswordSecretVersion object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        if hasattr(self, 'secret_data') and self.secret_data is not None:
            _dict['secret_data'] = self.secret_data
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsernamePasswordSecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsernamePasswordSecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsernamePasswordSecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class UsernamePasswordSecretVersionInfo(SecretVersionInfo):
    """
    UsernamePasswordSecretVersionInfo.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a UsernamePasswordSecretVersionInfo object.

        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretVersionInfo':
        """Initialize a UsernamePasswordSecretVersionInfo object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsernamePasswordSecretVersionInfo object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsernamePasswordSecretVersionInfo object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsernamePasswordSecretVersionInfo') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsernamePasswordSecretVersionInfo') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

class UsernamePasswordSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr bool payload_available: (optional) Indicates whether the payload for the
          secret version is stored and available.
    :attr bool downloaded: (optional) Indicates whether the secret data that is
          associated with a secret version was retrieved in a call to the service API.
    :attr int locks_total: (optional) The number of locks that are associated with a
          secret version.
    :attr dict version_custom_metadata: (optional) The secret version metadata that
          a user can customize.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 payload_available: bool = None,
                 downloaded: bool = None,
                 locks_total: int = None,
                 version_custom_metadata: dict = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a UsernamePasswordSecretVersionMetadata object.

        :param str id: (optional) The v4 UUID that uniquely identifies the secret.
        :param dict version_custom_metadata: (optional) The secret version metadata
               that a user can customize.
        :param bool auto_rotated: (optional) Indicates whether the version of the
               secret was created by automatic rotation.
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
        self.payload_available = payload_available
        self.downloaded = downloaded
        self.locks_total = locks_total
        self.version_custom_metadata = version_custom_metadata
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretVersionMetadata':
        """Initialize a UsernamePasswordSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'payload_available' in _dict:
            args['payload_available'] = _dict.get('payload_available')
        if 'downloaded' in _dict:
            args['downloaded'] = _dict.get('downloaded')
        if 'locks_total' in _dict:
            args['locks_total'] = _dict.get('locks_total')
        if 'version_custom_metadata' in _dict:
            args['version_custom_metadata'] = _dict.get('version_custom_metadata')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a UsernamePasswordSecretVersionMetadata object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and self.id is not None:
            _dict['id'] = self.id
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'payload_available') and getattr(self, 'payload_available') is not None:
            _dict['payload_available'] = getattr(self, 'payload_available')
        if hasattr(self, 'downloaded') and getattr(self, 'downloaded') is not None:
            _dict['downloaded'] = getattr(self, 'downloaded')
        if hasattr(self, 'locks_total') and getattr(self, 'locks_total') is not None:
            _dict['locks_total'] = getattr(self, 'locks_total')
        if hasattr(self, 'version_custom_metadata') and self.version_custom_metadata is not None:
            _dict['version_custom_metadata'] = self.version_custom_metadata
        if hasattr(self, 'auto_rotated') and self.auto_rotated is not None:
            _dict['auto_rotated'] = self.auto_rotated
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this UsernamePasswordSecretVersionMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'UsernamePasswordSecretVersionMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'UsernamePasswordSecretVersionMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other
