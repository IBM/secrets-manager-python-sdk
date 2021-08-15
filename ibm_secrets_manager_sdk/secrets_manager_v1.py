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

# IBM OpenAPI SDK Code Generator Version: 3.37.0-a85661cd-20210802-190136
 
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
from ibm_cloud_sdk_core.utils import convert_list, convert_model, datetime_to_string, string_to_datetime

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


    def create_config_element(self,
        secret_type: str,
        config_element: str,
        name: str,
        type: str,
        config: object,
        **kwargs
    ) -> DetailedResponse:
        """
        Create config element.

        Create a config element.

        :param str secret_type: The secret type.
        :param str config_element: The Config element type.
        :param str name: Config element name.
        :param str type: Dns provider config type.
        :param object config:
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if config_element is None:
            raise ValueError('config_element must be provided')
        if name is None:
            raise ValueError('name must be provided')
        if type is None:
            raise ValueError('type must be provided')
        if config is None:
            raise ValueError('config must be provided')
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
        Get config elements by type.

        Get a config elements.

        :param str secret_type: The secret type.
        :param str config_element: The Config element type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetConfigElements` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if config_element is None:
            raise ValueError('config_element must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config_elements')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
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


    def update_config_element(self,
        secret_type: str,
        config_element: str,
        config_name: str,
        type: str,
        config: object,
        **kwargs
    ) -> DetailedResponse:
        """
        Update config element.

        Update a config element.

        :param str secret_type: The secret type.
        :param str config_element: The Config element type.
        :param str config_name: Config name.
        :param str type: Dns provider config type.
        :param object config:
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if config_element is None:
            raise ValueError('config_element must be provided')
        if config_name is None:
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


    def delete_config_element(self,
        secret_type: str,
        config_element: str,
        config_name: str,
        **kwargs
    ) -> DetailedResponse:
        """
        Delete config element.

        Delete a config element.

        :param str secret_type: The secret type.
        :param str config_element: The Config element type.
        :param str config_name: Config name.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if config_element is None:
            raise ValueError('config_element must be provided')
        if config_name is None:
            raise ValueError('config_name must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='delete_config_element')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))

        path_param_keys = ['secret_type', 'config_element', 'config_name']
        path_param_values = self.encode_path_vars(secret_type, config_element, config_name)
        path_param_dict = dict(zip(path_param_keys, path_param_values))
        url = '/api/v1/config/{secret_type}/{config_element}/{config_name}'.format(**path_param_dict)
        request = self.prepare_request(method='DELETE',
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
        Get config element.

        Get a config element.

        :param str secret_type: The secret type.
        :param str config_element: The Config element type.
        :param str config_name: Config name.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSingleConfigElement` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if config_element is None:
            raise ValueError('config_element must be provided')
        if config_name is None:
            raise ValueError('config_name must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_config_element')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
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


    def put_config(self,
        secret_type: str,
        api_key: str,
        **kwargs
    ) -> DetailedResponse:
        """
        Configure secrets of a given type.

        Updates the configuration for the given secret type.

        :param str secret_type: The secret type.
        :param str api_key: An IBM Cloud API key that has the capability to create
               and manage service IDs.
               The API key must be assigned the Editor platform role on the Access Groups
               Service and the Operator platform role on the IAM Identity Service. For
               more information, see [Configuring the IAM secrets
               engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-iam-credentials#configure-iam-secrets-engine-api).
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if api_key is None:
            raise ValueError('api_key must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='put_config')
        headers.update(sdk_headers)

        data = {
            'api_key': api_key
        }
        data = {k: v for (k, v) in data.items() if v is not None}
        data = json.dumps(data)
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

        response = self.send(request, **kwargs)
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
        :rtype: DetailedResponse with `dict` result representing a `GetConfig` object
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

        response = self.send(request, **kwargs)
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
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPolicies` object
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

        Retrieves a list of policies that are associated with a specified secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str policy: (optional) The type of policy that is associated with
               the specified secret.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretPolicies` object
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

        response = self.send(request, **kwargs)
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

        response = self.send(request, **kwargs)
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

        response = self.send(request, **kwargs)
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

        response = self.send(request, **kwargs)
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

        response = self.send(request, **kwargs)
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

        Creates a secret or imports an existing value that you can use to access or
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
        :param List[str] groups: (optional) Filter secrets by groups.
               You can apply multiple filters by using a comma-separated list of secret
               group IDs. If you need to filter secrets that are in the default secret
               group, use the `default` keyword.
               **Usage:** To retrieve a list of secrets that are associated with an
               existing secret group or the default group, use
               `../secrets?groups={secret_group_ID},default`.
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

        response = self.send(request, **kwargs)
        return response


    def update_secret(self,
        secret_type: str,
        id: str,
        action: str,
        secret_action: 'SecretAction',
        **kwargs
    ) -> DetailedResponse:
        """
        Invoke an action on a secret.

        Invokes an action on a specified secret. This method supports the following
        actions:
        - `rotate`: Replace the value of an `arbitrary`, `username_password`,
        `public_cert` or `imported_cert` secret.
        - `delete_credentials`: Delete the API key that is associated with an
        `iam_credentials` secret.

        :param str secret_type: The secret type.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str action: The action to perform on the specified secret.
        :param SecretAction secret_action: The properties to update for the secret.
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
        if secret_action is None:
            raise ValueError('secret_action must be provided')
        if isinstance(secret_action, SecretAction):
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

        Retrieves a version of a secret by specifying the ID of the version or the alias
        `previous`.
        A successful request returns the secret data that is associated with the specified
        version of your secret, along with other metadata.

        :param str secret_type: The secret type. Supported options include:
               imported_cert.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretVersion` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        if version_id is None:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_version')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
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


    def get_secret_version_metadata(self,
        secret_type: str,
        id: str,
        version_id: str,
        **kwargs
    ) -> DetailedResponse:
        """
        Get secret version metadata.

        Retrieves secret version metadata by specifying the ID of the version or the alias
        `previous`.
        A successful request returns the metadata that is associated with the specified
        version of your secret.

        :param str secret_type: The secret type. Supported options include:
               imported_cert.
        :param str id: The v4 UUID that uniquely identifies the secret.
        :param str version_id: The v4 UUID that uniquely identifies the secret
               version. You can also use `previous` to retrieve the previous version.
               **Note:** To find the version ID of a secret, use the [Get secret
               metadata](#get-secret-metadata) method and check the response details.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse with `dict` result representing a `GetSecretVersionMetadata` object
        """

        if secret_type is None:
            raise ValueError('secret_type must be provided')
        if id is None:
            raise ValueError('id must be provided')
        if version_id is None:
            raise ValueError('version_id must be provided')
        headers = {}
        sdk_headers = get_sdk_headers(service_name=self.DEFAULT_SERVICE_NAME,
                                      service_version='V1',
                                      operation_id='get_secret_version_metadata')
        headers.update(sdk_headers)

        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
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
        secret](#get-secret) or [Get a version of a secret](#get-secret-version) methods.

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

        response = self.send(request, **kwargs)
        return response


class CreateConfigElementEnums:
    """
    Enums for create_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
    class ConfigElement(str, Enum):
        """
        The Config element type.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'


class GetConfigElementsEnums:
    """
    Enums for get_config_elements parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
    class ConfigElement(str, Enum):
        """
        The Config element type.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'


class UpdateConfigElementEnums:
    """
    Enums for update_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
    class ConfigElement(str, Enum):
        """
        The Config element type.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'


class DeleteConfigElementEnums:
    """
    Enums for delete_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
    class ConfigElement(str, Enum):
        """
        The Config element type.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'


class GetConfigElementEnums:
    """
    Enums for get_config_element parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        PUBLIC_CERT = 'public_cert'
    class ConfigElement(str, Enum):
        """
        The Config element type.
        """
        CERTIFICATE_AUTHORITIES = 'certificate_authorities'
        DNS_PROVIDERS = 'dns_providers'


class PutConfigEnums:
    """
    Enums for put_config parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        IAM_CREDENTIALS = 'iam_credentials'
        PUBLIC_CERT = 'public_cert'


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


class PutPolicyEnums:
    """
    Enums for put_policy parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type.
        """
        USERNAME_PASSWORD = 'username_password'
        PUBLIC_CERT = 'public_cert'
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
        PUBLIC_CERT = 'public_cert'
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
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        USERNAME_PASSWORD = 'username_password'


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
        USERNAME_PASSWORD = 'username_password'


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
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        USERNAME_PASSWORD = 'username_password'


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
        USERNAME_PASSWORD = 'username_password'
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
        IAM_CREDENTIALS = 'iam_credentials'
        IMPORTED_CERT = 'imported_cert'
        PUBLIC_CERT = 'public_cert'
        USERNAME_PASSWORD = 'username_password'


class GetSecretVersionEnums:
    """
    Enums for get_secret_version parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type. Supported options include: imported_cert.
        """
        IMPORTED_CERT = 'imported_cert'


class GetSecretVersionMetadataEnums:
    """
    Enums for get_secret_version_metadata parameters.
    """

    class SecretType(str, Enum):
        """
        The secret type. Supported options include: imported_cert.
        """
        IMPORTED_CERT = 'imported_cert'


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
        USERNAME_PASSWORD = 'username_password'


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
        USERNAME_PASSWORD = 'username_password'


##############################################################################
# Models
##############################################################################


class CertificateSecretData():
    """
    CertificateSecretData.

    :attr str certificate: (optional) The contents of the certificate.
    :attr str private_key: (optional) The private key that is associated with the
          certificate.
    :attr str intermediate: (optional) The intermediate certificate that is
          associated with the certificate.
    """

    def __init__(self,
                 *,
                 certificate: str = None,
                 private_key: str = None,
                 intermediate: str = None) -> None:
        """
        Initialize a CertificateSecretData object.

        :param str certificate: (optional) The contents of the certificate.
        :param str private_key: (optional) The private key that is associated with
               the certificate.
        :param str intermediate: (optional) The intermediate certificate that is
               associated with the certificate.
        """
        self.certificate = certificate
        self.private_key = private_key
        self.intermediate = intermediate

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretData':
        """Initialize a CertificateSecretData object from a json dictionary."""
        args = {}
        if 'certificate' in _dict:
            args['certificate'] = _dict.get('certificate')
        if 'private_key' in _dict:
            args['private_key'] = _dict.get('private_key')
        if 'intermediate' in _dict:
            args['intermediate'] = _dict.get('intermediate')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CertificateSecretData object from a json dictionary."""
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
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

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
        APPLICATION_VND_IBM_SECRETS_MANAGER_ERROR_JSON = 'application/vnd.ibm.secrets-manager.error+json'


class ConfigElementDef():
    """
    Config element.

    :attr str name: Config element name.
    :attr str type: Dns provider config type.
    :attr object config:
    """

    def __init__(self,
                 name: str,
                 type: str,
                 config: object) -> None:
        """
        Initialize a ConfigElementDef object.

        :param str name: Config element name.
        :param str type: Dns provider config type.
        :param object config:
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
            _dict['config'] = self.config
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

class ConfigElementMetadata():
    """
    Dns provider config metadata.

    :attr str name: Config element name.
    :attr str type: Dns provider config type.
    """

    def __init__(self,
                 name: str,
                 type: str) -> None:
        """
        Initialize a ConfigElementMetadata object.

        :param str name: Config element name.
        :param str type: Dns provider config type.
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

class GetConfig():
    """
    Configuration that is used to generate IAM credentials.

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
    Config elements.

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
                  ", ".join(['GetConfigElementsResourcesItemCertificateAuthoritiesConfig', 'GetConfigElementsResourcesItemDnsProvidersConfig']))
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
                  ", ".join(['PublicCertSecretEngineRootConfig', 'IAMCredentialsSecretEngineRootConfig']))
        raise Exception(msg)

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

class GetSecretPolicyRotationResourcesItem():
    """
    Properties that describe a rotation policy.

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
    :attr SecretPolicyRotationRotation rotation:
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
        Initialize a GetSecretPolicyRotationResourcesItem object.

        :param str id: The v4 UUID that uniquely identifies the policy.
        :param str type: The MIME type that represents the policy. Currently, only
               the default is supported.
        :param SecretPolicyRotationRotation rotation:
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
    def from_dict(cls, _dict: Dict) -> 'GetSecretPolicyRotationResourcesItem':
        """Initialize a GetSecretPolicyRotationResourcesItem object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        else:
            raise ValueError('Required property \'id\' not present in GetSecretPolicyRotationResourcesItem JSON')
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
            raise ValueError('Required property \'type\' not present in GetSecretPolicyRotationResourcesItem JSON')
        if 'rotation' in _dict:
            args['rotation'] = _dict.get('rotation')
        else:
            raise ValueError('Required property \'rotation\' not present in GetSecretPolicyRotationResourcesItem JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetSecretPolicyRotationResourcesItem object from a json dictionary."""
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
            if isinstance(self.rotation, dict):
                _dict['rotation'] = self.rotation
            else:
                _dict['rotation'] = self.rotation.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this GetSecretPolicyRotationResourcesItem object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'GetSecretPolicyRotationResourcesItem') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'GetSecretPolicyRotationResourcesItem') -> bool:
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other

    class TypeEnum(str, Enum):
        """
        The MIME type that represents the policy. Currently, only the default is
        supported.
        """
        APPLICATION_VND_IBM_SECRETS_MANAGER_SECRET_POLICY_JSON = 'application/vnd.ibm.secrets-manager.secret.policy+json'


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
    Config element.

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
            args['resources'] = [ConfigElementDef.from_dict(x) for x in _dict.get('resources')]
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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = [x.to_dict() for x in self.resources]
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

class IssuanceInfo():
    """
    Public certificate issuance info.

    :attr datetime ordered_on: (optional) The date the certificate was ordered. The
          date format follows RFC 3339.
    :attr str error_code: (optional) The issuance info error code.
    :attr str error_message: (optional) The issuance info error message.
    :attr bool bundle_certs: (optional)
    :attr int state: (optional) The secret state based on NIST SP 800-57. States are
          integers and correspond to the Pre-activation = 0, Active = 1,  Suspended = 2,
          Deactivated = 3, and Destroyed = 5 values.
    :attr str state_description: (optional) A text representation of the secret
          state.
    :attr bool auto_rotated: (optional)
    :attr str ca: (optional)
    :attr str dns: (optional)
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
                 dns: str = None) -> None:
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

class Rotation():
    """
    Rotation.

    :attr bool auto_rotate: (optional)
    :attr bool rotate_keys: (optional)
    """

    def __init__(self,
                 *,
                 auto_rotate: bool = None,
                 rotate_keys: bool = None) -> None:
        """
        Initialize a Rotation object.

        :param bool auto_rotate: (optional)
        :param bool rotate_keys: (optional)
        """
        self.auto_rotate = auto_rotate
        self.rotate_keys = rotate_keys

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'Rotation':
        """Initialize a Rotation object from a json dictionary."""
        args = {}
        if 'auto_rotate' in _dict:
            args['auto_rotate'] = _dict.get('auto_rotate')
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
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

class SecretAction():
    """
    SecretAction.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretAction object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
                  ", ".join(['RotateArbitrarySecretBody', 'RotatePublicCertBody', 'RotateUsernamePasswordSecretBody', 'RotateCertificateBody', 'DeleteCredentialsForIAMCredentialsSecret']))
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
        args.update({k:v for (k, v) in _dict.items() if k not in cls._properties})
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

class SecretMetadata():
    """
    SecretMetadata.

    """

    def __init__(self) -> None:
        """
        Initialize a SecretMetadata object.

        """
        msg = "Cannot instantiate base class. Instead, instantiate one of the defined subclasses: {0}".format(
                  ", ".join(['ArbitrarySecretMetadata', 'UsernamePasswordSecretMetadata', 'IAMCredentialsSecretMetadata', 'CertificateSecretMetadata', 'PublicCertificateMetadataSecretResource']))
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
                  ", ".join(['SecretPolicyRotationRotationPolicyRotation', 'SecretPolicyRotationRotationPublicCertPolicyRotation']))
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
                  ", ".join(['ArbitrarySecretResource', 'UsernamePasswordSecretResource', 'IAMCredentialsSecretResource', 'CertificateSecretResource', 'PublicCertificateSecretResource']))
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
                  ", ".join(['CertificateSecretVersion']))
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
                  ", ".join(['ArbitrarySecretVersionMetadata', 'UsernamePasswordSecretVersionMetadata', 'IAMCredentialsSecretVersionMetadata', 'CertificateSecretVersionMetadata']))
        raise Exception(msg)

class CertificateValidity():
    """
    CertificateValidity.

    :attr datetime not_before: (optional) The date the certificate validity period
          begins.
    :attr datetime not_after: (optional) The date the certificate validity period
          ends.
    """

    def __init__(self,
                 *,
                 not_before: datetime = None,
                 not_after: datetime = None) -> None:
        """
        Initialize a CertificateValidity object.

        :param datetime not_before: (optional) The date the certificate validity
               period begins.
        :param datetime not_after: (optional) The date the certificate validity
               period ends.
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
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions the secret has.
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
                 expiration_date: datetime = None) -> None:
        """
        Initialize a ArbitrarySecretMetadata object.

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
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr datetime expiration_date: (optional) The date the secret material expires.
          The date format follows RFC 3339.
          You can set an expiration date on supported secret types at their creation. If
          you create a secret without specifying an expiration date, the secret does not
          expire. The `expiration_date` field is supported for the following secret types:
          - `arbitrary`
          - `username_password`.
    :attr str payload: (optional) The new secret data to assign to the secret.
    :attr object secret_data: (optional)
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
                 expiration_date: datetime = None,
                 payload: str = None,
                 secret_data: object = None) -> None:
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


class ArbitrarySecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None) -> None:
        """
        Initialize a ArbitrarySecretVersionMetadata object.

        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'ArbitrarySecretVersionMetadata':
        """Initialize a ArbitrarySecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a ArbitrarySecretVersionMetadata object from a json dictionary."""
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
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions the secret has.
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str algorithm: (optional) The identifier for the cryptographic algorthim
          that was used by the issuing certificate authority to sign the ceritificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public key that is associated with the
          certificate.
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
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str description: (optional) An extended description of your secret.
               To protect your privacy, do not use personal data, such as your name or
               location, as a description for your secret.
        :param CertificateValidity validity: (optional)
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
        if hasattr(self, 'serial_number') and getattr(self, 'serial_number') is not None:
            _dict['serial_number'] = getattr(self, 'serial_number')
        if hasattr(self, 'algorithm') and getattr(self, 'algorithm') is not None:
            _dict['algorithm'] = getattr(self, 'algorithm')
        if hasattr(self, 'key_algorithm') and getattr(self, 'key_algorithm') is not None:
            _dict['key_algorithm'] = getattr(self, 'key_algorithm')
        if hasattr(self, 'issuer') and getattr(self, 'issuer') is not None:
            _dict['issuer'] = getattr(self, 'issuer')
        if hasattr(self, 'validity') and self.validity is not None:
            _dict['validity'] = self.validity.to_dict()
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
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr str certificate: (optional) The contents of your certificate. The data
          must be formatted on a single line with embedded newline characters.
    :attr str private_key: (optional) The private key to associate with the
          certificate. The data must be formatted on a single line with embedded newline
          characters.
    :attr str intermediate: (optional) The intermediate certificate to associate
          with the root certificate. The data must be formatted on a single line with
          embedded newline characters.
    :attr object secret_data: (optional)
    :attr str serial_number: (optional) The unique serial number that was assigned
          to the certificate by the issuing certificate authority.
    :attr str algorithm: (optional) The identifier for the cryptographic algorthim
          that was used by the issuing certificate authority to sign the ceritificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm that was used to generate the public key that is associated with the
          certificate.
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
                 certificate: str = None,
                 private_key: str = None,
                 intermediate: str = None,
                 secret_data: object = None,
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
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param str certificate: (optional) The contents of your certificate. The
               data must be formatted on a single line with embedded newline characters.
        :param str private_key: (optional) The private key to associate with the
               certificate. The data must be formatted on a single line with embedded
               newline characters.
        :param str intermediate: (optional) The intermediate certificate to
               associate with the root certificate. The data must be formatted on a single
               line with embedded newline characters.
        :param CertificateValidity validity: (optional)
        :param List[str] alt_names: (optional) The alternative names that are
               defined for the certificate.
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
        if hasattr(self, 'validity') and self.validity is not None:
            _dict['validity'] = self.validity.to_dict()
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


class CertificateSecretVersion(SecretVersion):
    """
    CertificateSecretVersion.

    :attr str id: (optional) The v4 UUID that uniquely identifies the secret.
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the secret.
    :attr str version_id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr CertificateValidity validity: (optional)
    :attr str serial_number: (optional)
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateSecretData secret_data: (optional)
    """

    def __init__(self,
                 *,
                 id: str = None,
                 crn: str = None,
                 version_id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 validity: 'CertificateValidity' = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 secret_data: 'CertificateSecretData' = None) -> None:
        """
        Initialize a CertificateSecretVersion object.

        :param CertificateValidity validity: (optional)
        :param str serial_number: (optional)
        :param CertificateSecretData secret_data: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.crn = crn
        self.version_id = version_id
        self.creation_date = creation_date
        self.created_by = created_by
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
        if 'crn' in _dict:
            args['crn'] = _dict.get('crn')
        if 'version_id' in _dict:
            args['version_id'] = _dict.get('version_id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
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
        if hasattr(self, 'crn') and getattr(self, 'crn') is not None:
            _dict['crn'] = getattr(self, 'crn')
        if hasattr(self, 'version_id') and getattr(self, 'version_id') is not None:
            _dict['version_id'] = getattr(self, 'version_id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'validity') and self.validity is not None:
            _dict['validity'] = self.validity.to_dict()
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'secret_data') and self.secret_data is not None:
            _dict['secret_data'] = self.secret_data.to_dict()
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

class CertificateSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    :attr str serial_number: (optional)
    :attr datetime expiration_date: (optional) The date that the certificate
          expires. The date format follows RFC 3339.
    :attr CertificateValidity validity: (optional)
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None,
                 serial_number: str = None,
                 expiration_date: datetime = None,
                 validity: 'CertificateValidity' = None) -> None:
        """
        Initialize a CertificateSecretVersionMetadata object.

        :param str serial_number: (optional)
        :param CertificateValidity validity: (optional)
        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.serial_number = serial_number
        self.expiration_date = expiration_date
        self.validity = validity

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'CertificateSecretVersionMetadata':
        """Initialize a CertificateSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
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
        if hasattr(self, 'id') and getattr(self, 'id') is not None:
            _dict['id'] = getattr(self, 'id')
        if hasattr(self, 'creation_date') and getattr(self, 'creation_date') is not None:
            _dict['creation_date'] = datetime_to_string(getattr(self, 'creation_date'))
        if hasattr(self, 'created_by') and getattr(self, 'created_by') is not None:
            _dict['created_by'] = getattr(self, 'created_by')
        if hasattr(self, 'serial_number') and self.serial_number is not None:
            _dict['serial_number'] = self.serial_number
        if hasattr(self, 'expiration_date') and getattr(self, 'expiration_date') is not None:
            _dict['expiration_date'] = datetime_to_string(getattr(self, 'expiration_date'))
        if hasattr(self, 'validity') and self.validity is not None:
            _dict['validity'] = self.validity.to_dict()
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

class DeleteCredentialsForIAMCredentialsSecret(SecretAction):
    """
    Delete the credentials that are associated with an `iam_credentials` secret.

    :attr str service_id: The service ID that you want to delete. It is deleted
          together with its API key.
    """

    def __init__(self,
                 service_id: str) -> None:
        """
        Initialize a DeleteCredentialsForIAMCredentialsSecret object.

        :param str service_id: The service ID that you want to delete. It is
               deleted together with its API key.
        """
        # pylint: disable=super-init-not-called
        self.service_id = service_id

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'DeleteCredentialsForIAMCredentialsSecret':
        """Initialize a DeleteCredentialsForIAMCredentialsSecret object from a json dictionary."""
        args = {}
        if 'service_id' in _dict:
            args['service_id'] = _dict.get('service_id')
        else:
            raise ValueError('Required property \'service_id\' not present in DeleteCredentialsForIAMCredentialsSecret JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a DeleteCredentialsForIAMCredentialsSecret object from a json dictionary."""
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
    Certificate authorities config.

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
            args['certificate_authorities'] = [ConfigElementMetadata.from_dict(x) for x in _dict.get('certificate_authorities')]
        else:
            raise ValueError('Required property \'certificate_authorities\' not present in GetConfigElementsResourcesItemCertificateAuthoritiesConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfigElementsResourcesItemCertificateAuthoritiesConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_authorities') and self.certificate_authorities is not None:
            _dict['certificate_authorities'] = [x.to_dict() for x in self.certificate_authorities]
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
    Dns providers config.

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
            args['dns_providers'] = [ConfigElementMetadata.from_dict(x) for x in _dict.get('dns_providers')]
        else:
            raise ValueError('Required property \'dns_providers\' not present in GetConfigElementsResourcesItemDnsProvidersConfig JSON')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetConfigElementsResourcesItemDnsProvidersConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'dns_providers') and self.dns_providers is not None:
            _dict['dns_providers'] = [x.to_dict() for x in self.dns_providers]
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
    :attr List[GetSecretPolicyRotationResourcesItem] resources: A collection of
          resources.
    """

    def __init__(self,
                 metadata: 'CollectionMetadata',
                 resources: List['GetSecretPolicyRotationResourcesItem']) -> None:
        """
        Initialize a GetSecretPolicyRotation object.

        :param CollectionMetadata metadata: The metadata that describes the
               resource array.
        :param List[GetSecretPolicyRotationResourcesItem] resources: A collection
               of resources.
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
            args['resources'] = [GetSecretPolicyRotationResourcesItem.from_dict(x) for x in _dict.get('resources')]
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
            _dict['metadata'] = self.metadata.to_dict()
        if hasattr(self, 'resources') and self.resources is not None:
            _dict['resources'] = [x.to_dict() for x in self.resources]
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
    Configuration that is used to generate IAM credentials.

    :attr str api_key: An IBM Cloud API key that has the capability to create and
          manage service IDs.
          The API key must be assigned the Editor platform role on the Access Groups
          Service and the Operator platform role on the IAM Identity Service. For more
          information, see [Configuring the IAM secrets
          engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-iam-credentials#configure-iam-secrets-engine-api).
    :attr str api_key_hash: (optional) The hash value of the IBM Cloud API key that
          is used to create and manage service IDs.
    """

    def __init__(self,
                 api_key: str,
                 *,
                 api_key_hash: str = None) -> None:
        """
        Initialize a IAMCredentialsSecretEngineRootConfig object.

        :param str api_key: An IBM Cloud API key that has the capability to create
               and manage service IDs.
               The API key must be assigned the Editor platform role on the Access Groups
               Service and the Operator platform role on the IAM Identity Service. For
               more information, see [Configuring the IAM secrets
               engine](https://cloud.ibm.com/docs/secrets-manager?topic=secrets-manager-iam-credentials#configure-iam-secrets-engine-api).
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
    Metadata properties that describe a iam_credentials secret.

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
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions the secret has.
    :attr object ttl: (optional) The time-to-live (TTL) or lease duration to assign
          to generated credentials.
          For `iam_credentials` secrets, the TTL defines for how long each generated API
          key remains valid. The value can be either an integer that specifies the number
          of seconds, or the string representation of a duration, such as `120m` or `24h`.
    :attr bool reuse_api_key: (optional) For `iam_credentials` secrets, this field
          controls whether to use the same service ID and API key for future read
          operations on this secret. If set to `true`, the service reuses the current
          credentials. If set to `false`, a new service ID and API key is generated each
          time that the secret is read or accessed.
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
                 ttl: object = None,
                 reuse_api_key: bool = None) -> None:
        """
        Initialize a IAMCredentialsSecretMetadata object.

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
        :param object ttl: (optional) The time-to-live (TTL) or lease duration to
               assign to generated credentials.
               For `iam_credentials` secrets, the TTL defines for how long each generated
               API key remains valid. The value can be either an integer that specifies
               the number of seconds, or the string representation of a duration, such as
               `120m` or `24h`.
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
        self.ttl = ttl
        self.reuse_api_key = reuse_api_key

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
        if 'ttl' in _dict:
            args['ttl'] = _dict.get('ttl')
        if 'reuse_api_key' in _dict:
            args['reuse_api_key'] = _dict.get('reuse_api_key')
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
        if hasattr(self, 'ttl') and self.ttl is not None:
            _dict['ttl'] = self.ttl
        if hasattr(self, 'reuse_api_key') and getattr(self, 'reuse_api_key') is not None:
            _dict['reuse_api_key'] = getattr(self, 'reuse_api_key')
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
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
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
                 ttl: object = None,
                 access_groups: List[str] = None,
                 api_key: str = None,
                 service_id: str = None,
                 reuse_api_key: bool = None) -> None:
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
        self.ttl = ttl
        self.access_groups = access_groups
        self.api_key = api_key
        self.service_id = service_id
        self.reuse_api_key = reuse_api_key

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


class IAMCredentialsSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
    """

    def __init__(self,
                 *,
                 id: str = None,
                 creation_date: datetime = None,
                 created_by: str = None) -> None:
        """
        Initialize a IAMCredentialsSecretVersionMetadata object.

        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'IAMCredentialsSecretVersionMetadata':
        """Initialize a IAMCredentialsSecretVersionMetadata object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'creation_date' in _dict:
            args['creation_date'] = string_to_datetime(_dict.get('creation_date'))
        if 'created_by' in _dict:
            args['created_by'] = _dict.get('created_by')
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a IAMCredentialsSecretVersionMetadata object from a json dictionary."""
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

class PublicCertSecretEngineRootConfig(GetConfigResourcesItem):
    """
    Configuration for `public_cert` secret.

    :attr List[ConfigElementMetadata] certificate_authorities: (optional)
          `public_cert` certificate authorites configuration.
    :attr List[ConfigElementMetadata] dns_providers: (optional) `public_cert` dns
          provider configuration.
    """

    def __init__(self,
                 *,
                 certificate_authorities: List['ConfigElementMetadata'] = None,
                 dns_providers: List['ConfigElementMetadata'] = None) -> None:
        """
        Initialize a PublicCertSecretEngineRootConfig object.

        :param List[ConfigElementMetadata] dns_providers: (optional) `public_cert`
               dns provider configuration.
        """
        # pylint: disable=super-init-not-called
        self.certificate_authorities = certificate_authorities
        self.dns_providers = dns_providers

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PublicCertSecretEngineRootConfig':
        """Initialize a PublicCertSecretEngineRootConfig object from a json dictionary."""
        args = {}
        if 'certificate_authorities' in _dict:
            args['certificate_authorities'] = [ConfigElementMetadata.from_dict(x) for x in _dict.get('certificate_authorities')]
        if 'dns_providers' in _dict:
            args['dns_providers'] = [ConfigElementMetadata.from_dict(x) for x in _dict.get('dns_providers')]
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PublicCertSecretEngineRootConfig object from a json dictionary."""
        return cls.from_dict(_dict)

    def to_dict(self) -> Dict:
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'certificate_authorities') and getattr(self, 'certificate_authorities') is not None:
            _dict['certificate_authorities'] = [x.to_dict() for x in getattr(self, 'certificate_authorities')]
        if hasattr(self, 'dns_providers') and self.dns_providers is not None:
            _dict['dns_providers'] = [x.to_dict() for x in self.dns_providers]
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

class PublicCertificateMetadataSecretResource(SecretMetadata):
    """
    Metadata properties that describe a public certificate secret.

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
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions the secret has.
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr bool bundle_certs: (optional)
    :attr str algorithm: (optional) The identifier for the cryptographic algorthim
          to be used by the issuing certificate authority to sign the ceritificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm to be used to generate the public key that is associated with the
          certificate.
    :attr List[str] alt_names: (optional) The alternative names that are defined for
          the certificate.
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr bool private_key_included: (optional)
    :attr bool intermediate_included: (optional)
    :attr Rotation rotation: (optional)
    :attr IssuanceInfo issuance_info: (optional) Public certificate issuance info.
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
                 issuer: str = None,
                 bundle_certs: bool = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 alt_names: List[str] = None,
                 common_name: str = None,
                 private_key_included: bool = None,
                 intermediate_included: bool = None,
                 rotation: 'Rotation' = None,
                 issuance_info: 'IssuanceInfo' = None) -> None:
        """
        Initialize a PublicCertificateMetadataSecretResource object.

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
        :param bool bundle_certs: (optional)
        :param str key_algorithm: (optional) The identifier for the cryptographic
               algorithm to be used to generate the public key that is associated with the
               certificate.
        :param List[str] alt_names: (optional) The alternative names that are
               defined for the certificate.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param Rotation rotation: (optional)
        :param IssuanceInfo issuance_info: (optional) Public certificate issuance
               info.
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
        self.issuer = issuer
        self.bundle_certs = bundle_certs
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.alt_names = alt_names
        self.common_name = common_name
        self.private_key_included = private_key_included
        self.intermediate_included = intermediate_included
        self.rotation = rotation
        self.issuance_info = issuance_info

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'PublicCertificateMetadataSecretResource':
        """Initialize a PublicCertificateMetadataSecretResource object from a json dictionary."""
        args = {}
        if 'id' in _dict:
            args['id'] = _dict.get('id')
        if 'labels' in _dict:
            args['labels'] = _dict.get('labels')
        if 'name' in _dict:
            args['name'] = _dict.get('name')
        else:
            raise ValueError('Required property \'name\' not present in PublicCertificateMetadataSecretResource JSON')
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
        if 'private_key_included' in _dict:
            args['private_key_included'] = _dict.get('private_key_included')
        if 'intermediate_included' in _dict:
            args['intermediate_included'] = _dict.get('intermediate_included')
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'issuance_info' in _dict:
            args['issuance_info'] = IssuanceInfo.from_dict(_dict.get('issuance_info'))
        return cls(**args)

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a PublicCertificateMetadataSecretResource object from a json dictionary."""
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
        if hasattr(self, 'private_key_included') and getattr(self, 'private_key_included') is not None:
            _dict['private_key_included'] = getattr(self, 'private_key_included')
        if hasattr(self, 'intermediate_included') and getattr(self, 'intermediate_included') is not None:
            _dict['intermediate_included'] = getattr(self, 'intermediate_included')
        if hasattr(self, 'rotation') and self.rotation is not None:
            _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'issuance_info') and self.issuance_info is not None:
            _dict['issuance_info'] = self.issuance_info.to_dict()
        return _dict

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        return self.to_dict()

    def __str__(self) -> str:
        """Return a `str` version of this PublicCertificateMetadataSecretResource object."""
        return json.dumps(self.to_dict(), indent=2)

    def __eq__(self, other: 'PublicCertificateMetadataSecretResource') -> bool:
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other: 'PublicCertificateMetadataSecretResource') -> bool:
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
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
    :attr str issuer: (optional) The distinguished name that identifies the entity
          that signed and issued the certificate.
    :attr bool bundle_certs: (optional)
    :attr str ca: (optional) The configured ca name.
    :attr str dns: (optional) The configured dns provider.
    :attr str algorithm: (optional) The identifier for the cryptographic algorthim
          to be used by the issuing certificate authority to sign the ceritificate.
    :attr str key_algorithm: (optional) The identifier for the cryptographic
          algorithm to be used to generate the public key that is associated with the
          certificate.
    :attr List[str] alt_names: (optional) The alternative names that are defined for
          the certificate.
    :attr str common_name: (optional) The fully qualified domain name or host domain
          name for the certificate.
    :attr Rotation rotation: (optional)
    :attr IssuanceInfo issuance_info: (optional) Public certificate issuance info.
    :attr object secret_data: (optional)
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
                 issuer: str = None,
                 bundle_certs: bool = None,
                 ca: str = None,
                 dns: str = None,
                 algorithm: str = None,
                 key_algorithm: str = None,
                 alt_names: List[str] = None,
                 common_name: str = None,
                 rotation: 'Rotation' = None,
                 issuance_info: 'IssuanceInfo' = None,
                 secret_data: object = None) -> None:
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
               Up to 30 labels can be created. Labels can be between 2-30 characters,
               including spaces. Special characters not permitted include the angled
               bracket, comma, colon, ampersand, and vertical pipe character (|).
               To protect your privacy, do not use personal data, such as your name or
               location, as a label for your secret.
        :param bool bundle_certs: (optional)
        :param str ca: (optional) The configured ca name.
        :param str dns: (optional) The configured dns provider.
        :param str key_algorithm: (optional) The identifier for the cryptographic
               algorithm to be used to generate the public key that is associated with the
               certificate.
        :param List[str] alt_names: (optional) The alternative names that are
               defined for the certificate.
        :param str common_name: (optional) The fully qualified domain name or host
               domain name for the certificate.
        :param Rotation rotation: (optional)
        :param IssuanceInfo issuance_info: (optional) Public certificate issuance
               info.
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
        self.issuer = issuer
        self.bundle_certs = bundle_certs
        self.ca = ca
        self.dns = dns
        self.algorithm = algorithm
        self.key_algorithm = key_algorithm
        self.alt_names = alt_names
        self.common_name = common_name
        self.rotation = rotation
        self.issuance_info = issuance_info
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
        if 'rotation' in _dict:
            args['rotation'] = Rotation.from_dict(_dict.get('rotation'))
        if 'issuance_info' in _dict:
            args['issuance_info'] = IssuanceInfo.from_dict(_dict.get('issuance_info'))
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
        if hasattr(self, 'rotation') and self.rotation is not None:
            _dict['rotation'] = self.rotation.to_dict()
        if hasattr(self, 'issuance_info') and self.issuance_info is not None:
            _dict['issuance_info'] = self.issuance_info.to_dict()
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


    class KeyAlgorithmEnum(str, Enum):
        """
        The identifier for the cryptographic algorithm to be used to generate the public
        key that is associated with the certificate.
        """
        RSA2048 = 'RSA2048'
        RSA4096 = 'RSA4096'
        EC256 = 'EC256'
        EC384 = 'EC384'


class RotateArbitrarySecretBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr str payload: The new secret data to assign to an `arbitrary` secret.
    """

    def __init__(self,
                 payload: str) -> None:
        """
        Initialize a RotateArbitrarySecretBody object.

        :param str payload: The new secret data to assign to an `arbitrary` secret.
        """
        # pylint: disable=super-init-not-called
        self.payload = payload

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateArbitrarySecretBody':
        """Initialize a RotateArbitrarySecretBody object from a json dictionary."""
        args = {}
        if 'payload' in _dict:
            args['payload'] = _dict.get('payload')
        else:
            raise ValueError('Required property \'payload\' not present in RotateArbitrarySecretBody JSON')
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
    """

    def __init__(self,
                 certificate: str,
                 *,
                 private_key: str = None,
                 intermediate: str = None) -> None:
        """
        Initialize a RotateCertificateBody object.

        :param str certificate: The new data to associate with the certificate.
        :param str private_key: (optional) The new private key to associate with
               the certificate.
        :param str intermediate: (optional) The new intermediate certificate to
               associate with the certificate.
        """
        # pylint: disable=super-init-not-called
        self.certificate = certificate
        self.private_key = private_key
        self.intermediate = intermediate

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

class RotatePublicCertBody(SecretAction):
    """
    The request body of a `rotate` action.

    :attr bool rotate_keys: Determine whether keys should be rotated.
    """

    def __init__(self,
                 rotate_keys: bool) -> None:
        """
        Initialize a RotatePublicCertBody object.

        :param bool rotate_keys: Determine whether keys should be rotated.
        """
        # pylint: disable=super-init-not-called
        self.rotate_keys = rotate_keys

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotatePublicCertBody':
        """Initialize a RotatePublicCertBody object from a json dictionary."""
        args = {}
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
        else:
            raise ValueError('Required property \'rotate_keys\' not present in RotatePublicCertBody JSON')
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
    """

    def __init__(self,
                 password: str) -> None:
        """
        Initialize a RotateUsernamePasswordSecretBody object.

        :param str password: The new password to assign to a `username_password`
               secret.
        """
        # pylint: disable=super-init-not-called
        self.password = password

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'RotateUsernamePasswordSecretBody':
        """Initialize a RotateUsernamePasswordSecretBody object from a json dictionary."""
        args = {}
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        else:
            raise ValueError('Required property \'password\' not present in RotateUsernamePasswordSecretBody JSON')
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

    :attr int interval: Specifies the length of the secret rotation time interval.
    :attr str unit: Specifies the units for the secret rotation time interval.
    """

    def __init__(self,
                 interval: int,
                 unit: str) -> None:
        """
        Initialize a SecretPolicyRotationRotationPolicyRotation object.

        :param int interval: Specifies the length of the secret rotation time
               interval.
        :param str unit: Specifies the units for the secret rotation time interval.
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
            raise ValueError('Required property \'interval\' not present in SecretPolicyRotationRotationPolicyRotation JSON')
        if 'unit' in _dict:
            args['unit'] = _dict.get('unit')
        else:
            raise ValueError('Required property \'unit\' not present in SecretPolicyRotationRotationPolicyRotation JSON')
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
        Specifies the units for the secret rotation time interval.
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
            raise ValueError('Required property \'auto_rotate\' not present in SecretPolicyRotationRotationPublicCertPolicyRotation JSON')
        if 'rotate_keys' in _dict:
            args['rotate_keys'] = _dict.get('rotate_keys')
        else:
            raise ValueError('Required property \'rotate_keys\' not present in SecretPolicyRotationRotationPublicCertPolicyRotation JSON')
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

class UsernamePasswordSecretMetadata(SecretMetadata):
    """
    Metadata properties that describe a username_password secret.

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
    :attr str crn: (optional) The Cloud Resource Name (CRN) that uniquely identifies
          the resource.
    :attr datetime creation_date: (optional) The date the secret was created. The
          date format follows RFC 3339.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret.
    :attr datetime last_update_date: (optional) Updates when any part of the secret
          metadata is modified. The date format follows RFC 3339.
    :attr int versions_total: (optional) The number of versions the secret has.
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
                 expiration_date: datetime = None) -> None:
        """
        Initialize a UsernamePasswordSecretMetadata object.

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
    :attr int versions_total: (optional) The number of versions that are associated
          with a secret.
    :attr List[dict] versions: (optional) An array that contains metadata for each
          secret version. For more information on the metadata properties, see [Get secret
          version metadata](#get-secret-version-metadata).
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
                 username: str = None,
                 password: str = None,
                 secret_data: object = None,
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


class UsernamePasswordSecretVersionMetadata(SecretVersionMetadata):
    """
    Properties that describe a secret version.

    :attr str id: (optional) The ID of the secret version.
    :attr datetime creation_date: (optional) The date that the version of the secret
          was created.
    :attr str created_by: (optional) The unique identifier for the entity that
          created the secret version.
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
        Initialize a UsernamePasswordSecretVersionMetadata object.

        """
        # pylint: disable=super-init-not-called
        self.id = id
        self.creation_date = creation_date
        self.created_by = created_by
        self.auto_rotated = auto_rotated

    @classmethod
    def from_dict(cls, _dict: Dict) -> 'UsernamePasswordSecretVersionMetadata':
        """Initialize a UsernamePasswordSecretVersionMetadata object from a json dictionary."""
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
        """Initialize a UsernamePasswordSecretVersionMetadata object from a json dictionary."""
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
