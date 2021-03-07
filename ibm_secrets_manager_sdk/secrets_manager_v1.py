# coding: utf-8

# (C) Copyright IBM Corp. 2021.
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

# IBM OpenAPI SDK Code Generator Version: 3.29.0-cd9ba74f-20210305-183535

"""
With IBM Cloud® Secrets Manager, you can create, lease, and centrally manage secrets that
are used in IBM Cloud services or your custom-built applications. Secrets are stored in a
dedicated instance of Secrets Manager, built on open source HashiCorp Vault.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List
import json

from ibm_cloud_sdk_core import BaseService, DetailedResponse
from ibm_cloud_sdk_core.authenticators.authenticator import Authenticator
from ibm_cloud_sdk_core.get_authenticator import get_authenticator_from_environment
from ibm_cloud_sdk_core.utils import convert_model, datetime_to_string, string_to_datetime

from .common import get_sdk_headers


##############################################################################
# Service
##############################################################################

class SecretsManagerV1(BaseService):
    """The secrets-manager V1 service."""

    DEFAULT_SERVICE_URL = 'https://secrets-manager.cloud.ibm.com'
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
               Get up to date information from https://github.com/IBM/python-sdk-core/blob/master/README.md
               about initializing the authenticator of your choice.
        """
        BaseService.__init__(self,
                             service_url=self.DEFAULT_SERVICE_URL,
                             authenticator=authenticator)

    #########################
    # config
    #########################

    def put_config(self,
                   secret_type: str,
                   engine_config_one_of: 'EngineConfigOneOf',
                   **kwargs
                   ) -> DetailedResponse:
        """
        Configure secrets of a given type.

        Updates the configuration for the given secret type.

        :param str secret_type: The secret type.
        :param EngineConfigOneOf engine_config_one_of: The base request for setting
               secret engine configuration.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if engine_config_one_of is None:
            raise ValueError('engine_config_one_of must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='put_config')
        headers.update(sdk_headers)

        data = json.dumps(engine_config_one_of)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request)
        return response

    def get_config(self,
                   secret_type: str,
                   **kwargs
                   ) -> DetailedResponse:
        """
        Get the configuration for a secret type.

        Retrieves the configuration that is associated with the given secret type.

        :param str secret_type: The secret type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `EngineConfigOneOf` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    #########################
    # policies
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

        Creates or updates one or more policies, such as an [automatic rotation
        policy](http://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-rotate-secrets#auto-rotate-secret),
        for the specified secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretPolicyRotation] resources: A collection of resources.
        :param str policy: (optional) The type of policy that is associated with
               the specified secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPoliciesOneOf` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
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

        response = self.send(request)
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

        Retrieves a list of policies that are associated with a specified secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str policy: (optional) The type of policy that is associated with
               the specified secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPoliciesOneOf` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
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
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/policies'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request)
        return response

    #########################
    # secretGroups
    #########################

    def create_secret_group(self,
                            metadata: 'CollectionMetadata',
                            resources: List['SecretGroupResource'],
                            **kwargs
                            ) -> DetailedResponse:
        """
        Create a secret group.

        Creates a secret group that you can use to organize secrets and control who on
        your team has access to them.
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
        headers['Accept'] = 'application/json'

        url = '/api/v1/secret_groups'
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request)
        return response

    def list_secret_groups(self,
                           **kwargs
                           ) -> DetailedResponse:
        """
        List secret groups.

        Retrieves the list of secret groups that are available in your Secrets Manager
        instance.

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
        headers['Accept'] = 'application/json'

        url = '/api/v1/secret_groups'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    def get_secret_group(self,
                         id: str,
                         **kwargs
                         ) -> DetailedResponse:
        """
        Get a secret group.

        Retrieves the metadata of an existing secret group by specifying the ID of the
        group.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        if id is None:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_group')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    def update_secret_group_metadata(self,
                                     id: str,
                                     metadata: 'CollectionMetadata',
                                     resources: List['SecretGroupMetadataUpdatable'],
                                     **kwargs
                                     ) -> DetailedResponse:
        """
        Update a secret group.

        Updates the metadata of an existing secret group, such as its name or description.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretGroupMetadataUpdatable] resources: A collection of
               resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretGroupDef` object
        """

        if id is None:
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
        headers['Accept'] = 'application/json'

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request)
        return response

    def delete_secret_group(self,
                            id: str,
                            **kwargs
                            ) -> DetailedResponse:
        """
        Delete a secret group.

        Deletes a secret group by specifying the ID of the secret group.
        **Note:** To delete a secret group, it must be empty. If you need to remove a
        secret group that contains secrets, you must first [delete the
        secrets](#delete-secret) that are associated with the group.

        :param str id: The v4 UUID that uniquely identifies the secret group.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if id is None:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_secret_group')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))

        path_param_keys = ['id']
        path_param_values = self.encode_path_vars(id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secret_groups/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    #########################
    # secrets
    #########################

    def create_secret(self,
                      secret_type: str,
                      metadata: 'CollectionMetadata',
                      resources: List['SecretResource'],
                      **kwargs
                      ) -> DetailedResponse:
        """
        Create a secret.

        Creates a secret that you can use to access or authenticate to a protected
        resource.
        A successful request stores the secret in your dedicated instance based on the
        secret type and data that you specify. The response returns the ID value of the
        secret, along with other metadata.
        To learn more about the types of secrets that you can create with Secrets Manager,
        check out the
        [docs](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-basics).

        :param str secret_type: The secret type.
        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[SecretResource] resources: A collection of resources.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `CreateSecret` object
        """

        if secret_type is None:
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
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='POST',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request)
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

        Retrieves a list of secrets based on the type that you specify.

        :param str secret_type: The secret type.
        :param int limit: (optional) The number of secrets to retrieve. By default,
               list operations return the first 200 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 secrets in your instance, and you want to
               retrieve only the first 5 secrets, use
               `../secrets/{secret-type}?limit=5`.
        :param int offset: (optional) The number of secrets to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 secrets in your instance, and you want to
               retrieve secrets 26 through 50, use
               `../secrets/{secret-type}?offset=25&limit=25`.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `ListSecrets` object
        """

        if secret_type is None:
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
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type']
        path_param_values = self.encode_path_vars(secret_type)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request)
        return response

    def list_all_secrets(self,
                         *,
                         limit: int = None,
                         offset: int = None,
                         search: str = None,
                         sort_by: str = None,
                         **kwargs
                         ) -> DetailedResponse:
        """
        List all secrets.

        Retrieves a list of all secrets in your Secrets Manager instance.

        :param int limit: (optional) The number of secrets to retrieve. By default,
               list operations return the first 200 items. To retrieve a different set of
               items, use `limit` with `offset` to page through your available resources.
               **Usage:** If you have 20 secrets in your instance, and you want to
               retrieve only the first 5 secrets, use
               `../secrets/{secret-type}?limit=5`.
        :param int offset: (optional) The number of secrets to skip. By specifying
               `offset`, you retrieve a subset of items that starts with the `offset`
               value. Use `offset` with `limit` to page through your available resources.
               **Usage:** If you have 100 secrets in your instance, and you want to
               retrieve secrets 26 through 50, use
               `../secrets/{secret-type}?offset=25&limit=25`.
        :param str search: (optional) Filter secrets that contain the specified
               string. The fields that are searched include: id, name, description,
               labels, secret_type.
               **Usage:** If you want to list only the secrets that contain the string
               "text", use
               `../secrets/{secret-type}?search=text`.
        :param str sort_by: (optional) Sort a list of secrets by the specified
               field.
               **Usage:** To sort a list of secrets by their creation date, use
               `../secrets/{secret-type}?sort_by=creation_date`.
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
            'sort_by': sort_by
        }

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        headers['Accept'] = 'application/json'

        url = '/api/v1/secrets'
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers,
                                       params=params)

        response = self.send(request)
        return response

    def get_secret(self,
                   secret_type: str,
                   id: str,
                   **kwargs
                   ) -> DetailedResponse:
        """
        Get a secret.

        Retrieves a secret and its details by specifying the ID of the secret.
        A successful request returns the secret data that is associated with your secret,
        along with other metadata. To view only the details of a specified secret without
        retrieving its value, use the [Get secret metadata](#get-secret-metadata) method.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecret` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    def update_secret(self,
                      secret_type: str,
                      id: str,
                      action: str,
                      secret_action_one_of: 'SecretActionOneOf',
                      **kwargs
                      ) -> DetailedResponse:
        """
        Invoke an action on a secret.

        Invokes an action on a specified secret. This method supports the following
        actions:
        - `rotate`: Replace the value of an `arbitrary` or `username_password` secret.
        - `delete_credentials`: Delete the API key that is associated with an
        `iam_credentials` secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str action: The action to perform on the specified secret.
        :param SecretActionOneOf secret_action_one_of: The base request for
               invoking an action on a secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecret` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        if action is None:
            raise ValueError('action must be provided')
        if secret_action_one_of is None:
            raise ValueError('secret_action_one_of must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='update_secret')
        headers.update(sdk_headers)

        params = {
            'action': action
        }

        data = json.dumps(secret_action_one_of)
        headers['content-type'] = 'application/json'

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
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

        response = self.send(request)
        return response

    def delete_secret(self,
                      secret_type: str,
                      id: str,
                      **kwargs
                      ) -> DetailedResponse:
        """
        Delete a secret.

        Deletes a secret by specifying the ID of the secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_secret')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
        return response

    def get_secret_metadata(self,
                            secret_type: str,
                            id: str,
                            **kwargs
                            ) -> DetailedResponse:
        """
        Get secret metadata.

        Retrieves the details of a secret by specifying the ID.
        A successful request returns only metadata about the secret, such as its name and
        creation date. To retrieve the value of a secret, use the [Get a
        secret](#get-secret) method.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `SecretMetadataRequest` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_metadata')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='GET',
                                       url=url,
                                       headers=headers)

        response = self.send(request)
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

        Updates the metadata of a secret, such as its name or description.
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

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
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
        headers['Accept'] = 'application/json'

        path_param_keys = ['secret_type', 'id']
        path_param_values = self.encode_path_vars(secret_type, id)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/secrets/{secret_type}/{id}/metadata'.format(**path_param_dict)
        request = self.prepare_request(method='PUT',
                                       url=url,
                                       headers=headers,
                                       data=data)

        response = self.send(request)
        return response


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


class PutPolicyEnums:
    """
    Enums for put_policy parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        USERNAME_PASSWORD = 'username_password'

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

    class Policy(str, Enum):
        """
        The type of policy that is associated with the specified secret.
        """
        ROTATION = 'rotation'


class CreateSecretEnums:
    """
    Enums for create_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class ListSecretsEnums:
    """
    Enums for list_secrets parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class ListAllSecretsEnums:
    """
    Enums for list_all_secrets parameters.
    """

    class SortBy(str, Enum):
        """
        Sort a list of secrets by the specified field.
        **Usage:** To sort a list of secrets by their creation date, use
        `../secrets/{secret-type}?sort_by=creation_date`.
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
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class UpdateSecretEnums:
    """
    Enums for update_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'

    class Action(str, Enum):
        """
        The action to perform on the specified secret.
        """
        ROTATE = 'rotate'
        DELETE_CREDENTIALS = 'delete_credentials'


class DeleteSecretEnums:
    """
    Enums for delete_secret parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class GetSecretMetadataEnums:
    """
    Enums for get_secret_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class UpdateSecretMetadataEnums:
    """
    Enums for update_secret_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


##############################################################################
# Models
##############################################################################


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
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_JSON = 'application/vnd.ibm.secrets-manager.secret+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_VERSION_JSON = 'application/vnd.ibm.secrets-manager.secret.version+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_POLICY_JSON = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_GROUP_JSON = 'application/vnd.ibm.secrets-manager.secret.group+json'
        APPLICATION_VND_IBM_SECRETS_MANAGER_ERROR_JSON = 'application/vnd.ibm.secrets-manager.error+json'


class CreateSecret():
    """
    The base schema for creating secrets.

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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for x in self.resources:
                if isinstance(x, dict):
                    resources_list.append(x)
                else:
                    resources_list.append(x.to_dict())
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


class EngineConfigOneOf():
    """
    EngineConfigOneOf.

    """

    def __init__(self) -> None:
        """
        Initialize a EngineConfigOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['EngineConfigOneOfIAMSecretEngineRootConfig']))
        raise Exception(msg)


class GetSecret():
    """
    The base schema for retrieving a secret.

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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for x in self.resources:
                if isinstance(x, dict):
                    resources_list.append(x)
                else:
                    resources_list.append(x.to_dict())
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


class GetSecretPoliciesOneOf():
    """
    GetSecretPoliciesOneOf.

    """

    def __init__(self) -> None:
        """
        Initialize a GetSecretPoliciesOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['GetSecretPoliciesOneOfGetSecretPolicyRotation']))
        raise Exception(msg)


class GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem():
    """
    Properties that are associated with a rotation policy.

    :attr str id: The v4 UUID that uniquely identifies the policy.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          your cloud resources.
    :attr datetime creation_date: (optional) The date the policy was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the policy.
    :attr datetime last_update_date: (optional) Updates when the policy is replaced
          or modified. The date format follows RFC 3339.
    :attr str updated_by: (optional) The unique identifier for the entity that
          updated the policy.
    :attr str type: The MIME type that represents the policy. Currently, only the
          default is supported.
    :attr SecretPolicyRotationRotation rotation: The secret rotation time interval.
    """

    def __init__(self,
                 id: str,
                 type: str,
                 rotation: 'SecretPolicyRotationRotation',
                 *,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None,
                 updated_by: str = None) -> None:
        """
        Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem object.

        :param str id: The v4 UUID that uniquely identifies the policy.
        :param str type: The MIME type that represents the policy. Currently, only
               the default is supported.
        :param SecretPolicyRotationRotation rotation: The secret rotation time
               interval.
        """
        self.id = id
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date
        self.updated_by = updated_by
        self.type = type
        self.rotation = rotation

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem':
        """Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        else:
            raise ValueError(
                'Required property \'id\' not present in GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem JSON')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        if 'updated_by' in _dict:
            args['updated_by'] = _dict.get('updated_by')
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        else:
            raise ValueError(
                'Required property \'type\' not present in GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem JSON')
        if 'rotation' in _dict:
            args['rotation'] = SecretPolicyRotationRotation.from_dict(_dict.get('rotation'))
        else:
            raise ValueError(
                'Required property \'rotation\' not present in GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        if hasattr(self, 'updated_by') and getattr(self, 'updated_by') is not None:
            _dict['updated_by'] = getattr(self, 'updated_by')
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
        if hasattr(self, 'rotation') and self.rotation is not None:
            _dict['rotation'] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The MIME type that represents the policy. Currently, only the default is
        supported.
        """
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_POLICY_JSON = 'application/vnd.ibm.secrets-manager.secret.policy+json'


class ListSecrets():
    """
    The base schema for listing secrets.

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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            resources_list = []
            for x in self.resources:
                if isinstance(x, dict):
                    resources_list.append(x)
                else:
                    resources_list.append(x.to_dict())
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


class SecretActionOneOf():
    """
    SecretActionOneOf.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretActionOneOf object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(
                ['SecretActionOneOfRotateArbitrarySecretBody', 'SecretActionOneOfRotateUsernamePasswordSecretBody',
                 'SecretActionOneOfDeleteCredentialsForIAMSecret']))
        raise Exception(msg)


class SecretGroupDef():
    """
    The base schema definition for a secret group.

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
            args['resources'] = [SecretGroupResource.from_dict(x) for x in _dict.get('resources')]
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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = [x.to_dict() for x in self.resources]
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
    Metadata properties that describe a secret group.

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
            if getattr(self, _key, None) is not None:
                _dict[_key] = getattr(self, _key)
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

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


class SecretMetadata():
    """
    Metadata properties that describe a secret.

    :attr str id: (optional) The unique ID of the secret.
    :attr List[str] labels: (optional) Labels that you can use to filter for secrets
          in your instance.
          Up to 30 labels can be created. Labels can be between 2-30 characters, including
          spaces. Special characters not permitted include the angled bracket, comma,
          colon, ampersand, and vertical pipe character (|).
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
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr object ttl: (optional) The time-to-live (TTL) or lease duration to assign
          to generated credentials.
          For `iam_credentials` secrets, the TTL defines for how long each generated API
          key remains valid. The value can be either an integer that specifies the number
          of seconds, or the string representation of a duration, such as `120m` or `24h`.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
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
                 expiration_date: datetime = None,
                 ttl: object = None,
                 crn: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 last_update_date: datetime = None) -> None:
        """
        Initialize a SecretMetadata object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        :param object ttl: (optional) The time-to-live (TTL) or lease duration to
               assign to generated credentials.
               For `iam_credentials` secrets, the TTL defines for how long each generated
               API key remains valid. The value can be either an integer that specifies
               the number of seconds, or the string representation of a duration, such as
               `120m` or `24h`.
        """
        self.id = id
        self.labels = labels
        self.name = name
        self.description = description
        self.secret_group_id = secret_group_id
        self.state = state
        self.state_description = state_description
        self.secret_type = secret_type
        self.expiration_date = expiration_date
        self.ttl = ttl
        self.crn = crn
        self.creation_date = creation_date
        self.created_by = created_by
        self.last_update_date = last_update_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretMetadata':
        """Initialize a SecretMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in SecretMetadata JSON')
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
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'last_update_date' in _dict:
            args['last_update_date'] = string_to_datetime(_dict.get('last_update_date'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretMetadata object from a json dictionary."""
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
        if hasattr(self, 'expiration_date') and self.expiration_date is not None:
            _dict['expiration_date'] = datetime_to_string(self.expiration_date)
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'last_update_date') and getattr(self, 'last_update_date') is not None:
            _dict['last_update_date'] = datetime_to_string(getattr(self, 'last_update_date'))
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretMetadata object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretMetadata') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretMetadata') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


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
            args['resources'] = [SecretMetadata.from_dict(x) for x in _dict.get('resources')]
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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = [x.to_dict() for x in self.resources]
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
    Properties that are associated with a rotation policy.

    :attr str type: The MIME type that represents the policy. Currently, only the
          default is supported.
    :attr SecretPolicyRotationRotation rotation: The secret rotation time interval.
    """

    def __init__(self,
                 type: str,
                 rotation: 'SecretPolicyRotationRotation') -> None:
        """
        Initialize a SecretPolicyRotation object.

        :param str type: The MIME type that represents the policy. Currently, only
               the default is supported.
        :param SecretPolicyRotationRotation rotation: The secret rotation time
               interval.
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
            args['rotation'] = SecretPolicyRotationRotation.from_dict(_dict.get('rotation'))
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
    The secret rotation time interval.

    :attr int interval: Specifies the length of the secret rotation time interval.
    :attr str unit: Specifies the units for the secret rotation time interval.
    """

    def __init__(self,
                 interval: int,
                 unit: str) -> None:
        """
        Initialize a SecretPolicyRotationRotation object.

        :param int interval: Specifies the length of the secret rotation time
               interval.
        :param str unit: Specifies the units for the secret rotation time interval.
        """
        self.interval = interval
        self.unit = unit

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretPolicyRotationRotation':
        """Initialize a SecretPolicyRotationRotation object from a json dictionary."""
        args = {}
        if 'interval' in _dict:
            args['interval'] = _dict.get('interval')
        else:
            raise ValueError('Required property \'interval\' not present in SecretPolicyRotationRotation JSON')
        if 'unit' in _dict:
            args['unit'] = _dict.get('unit')
        else:
            raise ValueError('Required property \'unit\' not present in SecretPolicyRotationRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretPolicyRotationRotation object from a json dictionary."""
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
        """Return a `str` version of this SecretPolicyRotationRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretPolicyRotationRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretPolicyRotationRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class UnitEnum(str, Enum):
        """
        Specifies the units for the secret rotation time interval.
        """
        DAY = 'day'
        MONTH = 'month'


class SecretResource():
    """
    SecretResource.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretResource object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
            ", ".join(['SecretResourceArbitrarySecretResource', 'SecretResourceUsernamePasswordSecretResource',
                       'SecretResourceIAMSecretResource']))
        raise Exception(msg)


class SecretVersion():
    """
    Properties that are associated with a specific secret version.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr bool auto_rotated: (optional) Indicates whether the version of the secret
          was created by automatic rotation.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 auto_rotated: bool = None) -> None:
        """
        Initialize a SecretVersion object.

        """
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretVersion':
        """Initialize a SecretVersion object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        if 'auto_rotated' in _dict:
            args['auto_rotated'] = _dict.get('auto_rotated')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretVersion object from a json dictionary."""
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
        if hasattr(self, 'auto_rotated') and getattr(self, 'auto_rotated') is not None:
            _dict['auto_rotated'] = getattr(self, 'auto_rotated')
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretVersion object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretVersion') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretVersion') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class EngineConfigOneOfIAMSecretEngineRootConfig(EngineConfigOneOf):
    """
    Configuration that is used to generate IAM credentials.

    :attr str api_key: An IBM Cloud API key that has the capability to create and
          manage service IDs.
          The API key must be assigned the Editor platform role on the Access Groups
          Service and the Operator platform role on the IAM Identity Service. For more
          information, see [Enabling the IAM secrets
          engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-engines#configure-iam-engine).
    :attr str api_key_hash: (optional) The hash value of the IBM Cloud API key that
          is used to create and manage service IDs.
    """

    def __init__(self,
                 api_key: str,
                 *,
                 api_key_hash: str = None) -> None:
        """
        Initialize a EngineConfigOneOfIAMSecretEngineRootConfig object.

        :param str api_key: An IBM Cloud API key that has the capability to create
               and manage service IDs.
               The API key must be assigned the Editor platform role on the Access Groups
               Service and the Operator platform role on the IAM Identity Service. For
               more information, see [Enabling the IAM secrets
               engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-secret-engines#configure-iam-engine).
        """
        # pylint: disable=super-init-not-called
        self.api_key = api_key
        self.api_key_hash = api_key_hash

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'EngineConfigOneOfIAMSecretEngineRootConfig':
        """Initialize a EngineConfigOneOfIAMSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        else:
            raise ValueError(
                'Required property \'api_key\' not present in EngineConfigOneOfIAMSecretEngineRootConfig JSON')
        if 'api_key_hash' in _dict:
            args['api_key_hash'] = _dict.get('api_key_hash')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a EngineConfigOneOfIAMSecretEngineRootConfig object from a json dictionary."""
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
        """Return a `str` version of this EngineConfigOneOfIAMSecretEngineRootConfig object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'EngineConfigOneOfIAMSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'EngineConfigOneOfIAMSecretEngineRootConfig') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetSecretPoliciesOneOfGetSecretPolicyRotation(GetSecretPoliciesOneOf):
    """
    The base schema for retrieving a policy that is associated with a secret.

    :attr CollectionMetadata metadata: The metadata that describes the resource
          array.
    :attr List[GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem]
          resources: A collection of resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem']) -> None:
        """
        Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem]
               resources: A collection of resources.
        """
        # pylint: disable=super-init-not-called
        self.metadata = metadata
        self.resources = resources

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'GetSecretPoliciesOneOfGetSecretPolicyRotation':
        """Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotation object from a json dictionary."""
        args = {}
        if 'metadata' in _dict:
            args['metadata'] = CollectionMetadata.from_dict(_dict.get('metadata'))
        else:
            raise ValueError(
                'Required property \'metadata\' not present in GetSecretPoliciesOneOfGetSecretPolicyRotation JSON')
        if 'resources' in _dict:
            args['resources'] = [GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem.from_dict(x) for x in
                                 _dict.get('resources')]
        else:
            raise ValueError(
                'Required property \'resources\' not present in GetSecretPoliciesOneOfGetSecretPolicyRotation JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretPoliciesOneOfGetSecretPolicyRotation object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'metadata') and self.metadata is not None:
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = [x.to_dict() for x in self.resources]
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretPoliciesOneOfGetSecretPolicyRotation object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretPoliciesOneOfGetSecretPolicyRotation') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretPoliciesOneOfGetSecretPolicyRotation') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SecretActionOneOfDeleteCredentialsForIAMSecret(SecretActionOneOf):
    """
    Delete the credentials that are associated with an `iam_credentials` secret.

    :attr str service_id: The service ID that you want to delete. It is deleted
          together with its API key.
    """

    def __init__(self,
                 service_id: str) -> None:
        """
        Initialize a SecretActionOneOfDeleteCredentialsForIAMSecret object.

        :param str service_id: The service ID that you want to delete. It is
               deleted together with its API key.
        """
        # pylint: disable=super-init-not-called
        self.service_id = service_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretActionOneOfDeleteCredentialsForIAMSecret':
        """Initialize a SecretActionOneOfDeleteCredentialsForIAMSecret object from a json dictionary."""
        args = {}
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        else:
            raise ValueError(
                'Required property \'service_id\' not present in SecretActionOneOfDeleteCredentialsForIAMSecret JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretActionOneOfDeleteCredentialsForIAMSecret object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'service_id') and self.service_id is not None:
            _dict['service_id'] = self.service_id
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretActionOneOfDeleteCredentialsForIAMSecret object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretActionOneOfDeleteCredentialsForIAMSecret') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretActionOneOfDeleteCredentialsForIAMSecret') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SecretActionOneOfRotateArbitrarySecretBody(SecretActionOneOf):
    """
    The request body of a `rotate` action.

    :attr str payload: The new secret data to assign to an `arbitrary` secret.
    """

    def __init__(self,
                 payload: str) -> None:
        """
        Initialize a SecretActionOneOfRotateArbitrarySecretBody object.

        :param str payload: The new secret data to assign to an `arbitrary` secret.
        """
        # pylint: disable=super-init-not-called
        self.payload = payload

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretActionOneOfRotateArbitrarySecretBody':
        """Initialize a SecretActionOneOfRotateArbitrarySecretBody object from a json dictionary."""
        args = {}
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        else:
            raise ValueError(
                'Required property \'payload\' not present in SecretActionOneOfRotateArbitrarySecretBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretActionOneOfRotateArbitrarySecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'payload') and self.payload is not None:
            _dict['payload'] = self.payload
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretActionOneOfRotateArbitrarySecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretActionOneOfRotateArbitrarySecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretActionOneOfRotateArbitrarySecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SecretActionOneOfRotateUsernamePasswordSecretBody(SecretActionOneOf):
    """
    The request body of a `rotate` action.

    :attr str password: The new password to assign to a `username_password` secret.
    """

    def __init__(self,
                 password: str) -> None:
        """
        Initialize a SecretActionOneOfRotateUsernamePasswordSecretBody object.

        :param str password: The new password to assign to a `username_password`
               secret.
        """
        # pylint: disable=super-init-not-called
        self.password = password

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretActionOneOfRotateUsernamePasswordSecretBody':
        """Initialize a SecretActionOneOfRotateUsernamePasswordSecretBody object from a json dictionary."""
        args = {}
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        else:
            raise ValueError(
                'Required property \'password\' not present in SecretActionOneOfRotateUsernamePasswordSecretBody JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretActionOneOfRotateUsernamePasswordSecretBody object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretActionOneOfRotateUsernamePasswordSecretBody object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretActionOneOfRotateUsernamePasswordSecretBody') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretActionOneOfRotateUsernamePasswordSecretBody') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SecretResourceArbitrarySecretResource(SecretResource):
    """
    The base schema for secrets.

    :attr str type: (optional) The MIME type that represents the secret.
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
          Up to 30 labels can be created. Labels can be between 2-30 characters, including
          spaces. Special characters not permitted include the angled bracket, comma,
          colon, ampersand, and vertical pipe character (|).
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
    :attr List[SecretVersion] versions: (optional) An array that contains metadata
          for each secret version.
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr str payload: (optional) The new secret data to assign to an `arbitrary`
          secret.
    :attr object secret_data: (optional)
    """

    def __init__(self,
                 name: str,
                 *,
                 type: str = None,
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
                 versions: List['SecretVersion'] = None,
                 expiration_date: datetime = None,
                 payload: str = None,
                 secret_data: object = None) -> None:
        """
        Initialize a SecretResourceArbitrarySecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str type: (optional) The MIME type that represents the secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param datetime expiration_date: (optional) The date the secret material
               expires. The date format follows RFC 3339.
               You can set an expiration date on supported secret types at their creation.
               If you create a secret without specifying an expiration date, the secret
               does not expire. The `expiration_date` field is supported for the following
               secret types:
               - `arbitrary`
               - `username_password`.
        :param str payload: (optional) The new secret data to assign to an
               `arbitrary` secret.
        """
        # pylint: disable=super-init-not-called
        self.type = type
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
        self.versions = versions
        self.expiration_date = expiration_date
        self.payload = payload
        self.secret_data = secret_data

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretResourceArbitrarySecretResource':
        """Initialize a SecretResourceArbitrarySecretResource object from a json dictionary."""
        args = {}
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in SecretResourceArbitrarySecretResource JSON')
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
        if 'versions' in _dict:
            args['versions'] = [SecretVersion.from_dict(x) for x in _dict.get('versions')]
        if 'expiration_date' in _dict:
            args['expiration_date'] = string_to_datetime(_dict.get('expiration_date'))
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        if 'secret_data' in _dict:
            args['secret_data'] = _dict.get('secret_data')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretResourceArbitrarySecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
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
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = [x.to_dict() for x in getattr(self, 'versions')]
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
        """Return a `str` version of this SecretResourceArbitrarySecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretResourceArbitrarySecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretResourceArbitrarySecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class SecretResourceIAMSecretResource(SecretResource):
    """
    The base schema for secrets.

    :attr str type: (optional) The MIME type that represents the secret.
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
          Up to 30 labels can be created. Labels can be between 2-30 characters, including
          spaces. Special characters not permitted include the angled bracket, comma,
          colon, ampersand, and vertical pipe character (|).
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
    :attr List[SecretVersion] versions: (optional) An array that contains metadata
          for each secret version.
    :attr object ttl: (optional) The time-to-live (TTL) or lease duration to assign
          to generated credentials.
          For `iam_credentials` secrets, the TTL defines for how long each generated API
          key remains valid. The value can be either an integer that specifies the number
          of seconds, or the string representation of a duration, such as `120m` or `24h`.
    :attr List[str] access_groups: (optional) The access groups that define the
          capabilities of the service ID and API key that are generated for an
          `iam_credentials` secret.
          **Tip:** To find the ID of an access group, go to **Manage > Access (IAM) >
          Access groups** in the IBM Cloud console. Select the access group to inspect,
          and click **Details** to view its ID.
    :attr str api_key: (optional) The API key that is generated for this secret.
          After the secret reaches the end of its lease (see the `ttl` field), the API key
          is deleted automatically. If you want to continue to use the same API key for
          future read operations, see the `reuse_api_key` field.
    :attr str service_id: (optional) The service ID under which the API key (see the
          `api_key` field) is created. This service ID is added to the access groups that
          you assign for this secret.
    :attr bool reuse_api_key: (optional) Set to `true` to reuse the service ID and
          API key for this secret.
          Use this field to control whether to use the same service ID and API key for
          future read operations on this secret. If set to `true`, the service reuses the
          current credentials. If set to `false`, a new service ID and API key is
          generated each time that the secret is read or accessed.
    """

    def __init__(self,
                 name: str,
                 *,
                 type: str = None,
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
                 versions: List['SecretVersion'] = None,
                 ttl: object = None,
                 access_groups: List[str] = None,
                 api_key: str = None,
                 service_id: str = None,
                 reuse_api_key: bool = None) -> None:
        """
        Initialize a SecretResourceIAMSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str type: (optional) The MIME type that represents the secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param object ttl: (optional) The time-to-live (TTL) or lease duration to
               assign to generated credentials.
               For `iam_credentials` secrets, the TTL defines for how long each generated
               API key remains valid. The value can be either an integer that specifies
               the number of seconds, or the string representation of a duration, such as
               `120m` or `24h`.
        :param List[str] access_groups: (optional) The access groups that define
               the capabilities of the service ID and API key that are generated for an
               `iam_credentials` secret.
               **Tip:** To find the ID of an access group, go to **Manage > Access (IAM) >
               Access groups** in the IBM Cloud console. Select the access group to
               inspect, and click **Details** to view its ID.
        :param bool reuse_api_key: (optional) Set to `true` to reuse the service ID
               and API key for this secret.
               Use this field to control whether to use the same service ID and API key
               for future read operations on this secret. If set to `true`, the service
               reuses the current credentials. If set to `false`, a new service ID and API
               key is generated each time that the secret is read or accessed.
        """
        # pylint: disable=super-init-not-called
        self.type = type
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
        self.versions = versions
        self.ttl = ttl
        self.access_groups = access_groups
        self.api_key = api_key
        self.service_id = service_id
        self.reuse_api_key = reuse_api_key

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretResourceIAMSecretResource':
        """Initialize a SecretResourceIAMSecretResource object from a json dictionary."""
        args = {}
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in SecretResourceIAMSecretResource JSON')
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
        if 'versions' in _dict:
            args['versions'] = [SecretVersion.from_dict(x) for x in _dict.get('versions')]
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'access_groups' in _dict:
            args['access_groups'] = _dict.get('access_groups')
        if 'api_key' in _dict:
            args['api_key'] = _dict.get('api_key')
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        if 'reuse_api_key' in _dict:
            args['reuse_api_key'] = _dict.get('reuse_api_key')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SecretResourceIAMSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
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
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = [x.to_dict() for x in getattr(self, 'versions')]
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'access_groups') and self.access_groups is not None:
            _dict['access_groups'] = self.access_groups
        if hasattr(self, 'api_key') and getattr(self, 'api_key') is not None:
            _dict['api_key'] = getattr(self, 'api_key')
        if hasattr(self, 'service_id') and getattr(self, 'service_id') is not None:
            _dict['service_id'] = getattr(self, 'service_id')
        if hasattr(self, 'reuse_api_key') and self.reuse_api_key is not None:
            _dict['reuse_api_key'] = self.reuse_api_key
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this SecretResourceIAMSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretResourceIAMSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretResourceIAMSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'


class SecretResourceUsernamePasswordSecretResource(SecretResource):
    """
    The base schema for secrets.

    :attr str type: (optional) The MIME type that represents the secret.
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
          Up to 30 labels can be created. Labels can be between 2-30 characters, including
          spaces. Special characters not permitted include the angled bracket, comma,
          colon, ampersand, and vertical pipe character (|).
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
    :attr List[SecretVersion] versions: (optional) An array that contains metadata
          for each secret version.
    :attr str username: (optional) The username to assign to this secret.
    :attr str password: (optional) The password to assign to this secret.
    :attr object secret_data: (optional)
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
                 type: str = None,
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
                 versions: List['SecretVersion'] = None,
                 username: str = None,
                 password: str = None,
                 secret_data: object = None,
                 expiration_date: datetime = None,
                 next_rotation_date: datetime = None) -> None:
        """
        Initialize a SecretResourceUsernamePasswordSecretResource object.

        :param str name: A human-readable alias to assign to your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as an alias for your secret.
        :param str type: (optional) The MIME type that represents the secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param str secret_group_id: (optional) The v4 UUID that uniquely identifies
               the secret group to assign to this secret.
               If you omit this parameter, your secret is assigned to the `default` secret
               group.
        :param List[str] labels: (optional) Labels that you can use to filter for
               secrets in your instance.
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
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
        self.type = type
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
        self.versions = versions
        self.username = username
        self.password = password
        self.secret_data = secret_data
        self.expiration_date = expiration_date
        self.next_rotation_date = next_rotation_date

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'SecretResourceUsernamePasswordSecretResource':
        """Initialize a SecretResourceUsernamePasswordSecretResource object from a json dictionary."""
        args = {}
        if 'type' in _dict:
            args['type'] = _dict.get('type')
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError(
                'Required property \'name\' not present in SecretResourceUsernamePasswordSecretResource JSON')
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
        if 'versions' in _dict:
            args['versions'] = [SecretVersion.from_dict(x) for x in _dict.get('versions')]
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
        """Initialize a SecretResourceUsernamePasswordSecretResource object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'type') and self.type is not None:
            _dict['type'] = self.type
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
        if hasattr(self, 'versions') and getattr(self, 'versions') is not None:
            _dict['versions'] = [x.to_dict() for x in getattr(self, 'versions')]
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
        """Return a `str` version of this SecretResourceUsernamePasswordSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'SecretResourceUsernamePasswordSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'SecretResourceUsernamePasswordSecretResource') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class SecretTypeEnum(str, Enum):
        """
        The secret type.
        """
        ARBITRARY = 'arbitrary'
        USERNAME_PASSWORD = 'username_password'
        IAM_CREDENTIALS = 'iam_credentials'
