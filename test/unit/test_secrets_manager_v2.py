# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2025.
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

"""
Unit Tests for SecretsManagerV2
"""

from datetime import datetime, timezone
from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
from ibm_cloud_sdk_core.utils import datetime_to_string, string_to_datetime
import inspect
import json
import os
import pytest
import re
import requests
import responses
import urllib
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

_service = SecretsManagerV2(
    authenticator=NoAuthAuthenticator()
)

_base_url = 'https://provide-here-your-smgr-instanceuuid.us-south.secrets-manager.appdomain.cloud'
_service.set_service_url(_base_url)


def preprocess_url(operation_path: str):
    """
    Returns the request url associated with the specified operation path.
    This will be base_url concatenated with a quoted version of operation_path.
    The returned request URL is used to register the mock response so it needs
    to match the request URL that is formed by the requests library.
    """

    # Form the request URL from the base URL and operation path.
    request_url = _base_url + operation_path

    # If the request url does NOT end with a /, then just return it as-is.
    # Otherwise, return a regular expression that matches one or more trailing /.
    if not request_url.endswith('/'):
        return request_url
    return re.compile(request_url.rstrip('/') + '/+')


def test_parameterized_url():
    """
    Test formatting the parameterized service URL with the default variable values.
    """
    default_formatted_url = 'https://provide-here-your-smgr-instanceuuid.us-south.secrets-manager.appdomain.cloud'
    assert SecretsManagerV2.construct_service_url() == default_formatted_url


##############################################################################
# Start of Service: SecretGroups
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateSecretGroup:
    """
    Test Class for create_secret_group
    """

    @responses.activate
    def test_create_secret_group_all_params(self):
        """
        create_secret_group()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        name = 'my-secret-group'
        description = 'Extended description for this group.'

        # Invoke method
        response = _service.create_secret_group(
            name,
            description=description,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['name'] == 'my-secret-group'
        assert req_body['description'] == 'Extended description for this group.'

    def test_create_secret_group_all_params_with_retries(self):
        # Enable retries and run test_create_secret_group_all_params.
        _service.enable_retries()
        self.test_create_secret_group_all_params()

        # Disable retries and run test_create_secret_group_all_params.
        _service.disable_retries()
        self.test_create_secret_group_all_params()

    @responses.activate
    def test_create_secret_group_value_error(self):
        """
        test_create_secret_group_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        name = 'my-secret-group'
        description = 'Extended description for this group.'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "name": name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_group(**req_copy)

    def test_create_secret_group_value_error_with_retries(self):
        # Enable retries and run test_create_secret_group_value_error.
        _service.enable_retries()
        self.test_create_secret_group_value_error()

        # Disable retries and run test_create_secret_group_value_error.
        _service.disable_retries()
        self.test_create_secret_group_value_error()


class TestListSecretGroups:
    """
    Test Class for list_secret_groups
    """

    @responses.activate
    def test_list_secret_groups_all_params(self):
        """
        list_secret_groups()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups')
        mock_response = '{"secret_groups": [{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}], "total_count": 0}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.list_secret_groups()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secret_groups_all_params_with_retries(self):
        # Enable retries and run test_list_secret_groups_all_params.
        _service.enable_retries()
        self.test_list_secret_groups_all_params()

        # Disable retries and run test_list_secret_groups_all_params.
        _service.disable_retries()
        self.test_list_secret_groups_all_params()


class TestGetSecretGroup:
    """
    Test Class for get_secret_group
    """

    @responses.activate
    def test_get_secret_group_all_params(self):
        """
        get_secret_group()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'

        # Invoke method
        response = _service.get_secret_group(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_group_all_params_with_retries(self):
        # Enable retries and run test_get_secret_group_all_params.
        _service.enable_retries()
        self.test_get_secret_group_all_params()

        # Disable retries and run test_get_secret_group_all_params.
        _service.disable_retries()
        self.test_get_secret_group_all_params()

    @responses.activate
    def test_get_secret_group_value_error(self):
        """
        test_get_secret_group_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_group(**req_copy)

    def test_get_secret_group_value_error_with_retries(self):
        # Enable retries and run test_get_secret_group_value_error.
        _service.enable_retries()
        self.test_get_secret_group_value_error()

        # Disable retries and run test_get_secret_group_value_error.
        _service.disable_retries()
        self.test_get_secret_group_value_error()


class TestUpdateSecretGroup:
    """
    Test Class for update_secret_group
    """

    @responses.activate
    def test_update_secret_group_all_params(self):
        """
        update_secret_group()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a SecretGroupPatch model
        secret_group_patch_model = {}
        secret_group_patch_model['name'] = 'my-secret-group'
        secret_group_patch_model['description'] = 'Extended description for this group.'

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'
        secret_group_patch = secret_group_patch_model

        # Invoke method
        response = _service.update_secret_group(
            id,
            secret_group_patch,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_group_patch

    def test_update_secret_group_all_params_with_retries(self):
        # Enable retries and run test_update_secret_group_all_params.
        _service.enable_retries()
        self.test_update_secret_group_all_params()

        # Disable retries and run test_update_secret_group_all_params.
        _service.disable_retries()
        self.test_update_secret_group_all_params()

    @responses.activate
    def test_update_secret_group_value_error(self):
        """
        test_update_secret_group_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        mock_response = '{"id": "default", "name": "my-secret-group", "description": "Extended description for this group.", "created_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "updated_at": "2022-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a SecretGroupPatch model
        secret_group_patch_model = {}
        secret_group_patch_model['name'] = 'my-secret-group'
        secret_group_patch_model['description'] = 'Extended description for this group.'

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'
        secret_group_patch = secret_group_patch_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "secret_group_patch": secret_group_patch,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_group(**req_copy)

    def test_update_secret_group_value_error_with_retries(self):
        # Enable retries and run test_update_secret_group_value_error.
        _service.enable_retries()
        self.test_update_secret_group_value_error()

        # Disable retries and run test_update_secret_group_value_error.
        _service.disable_retries()
        self.test_update_secret_group_value_error()


class TestDeleteSecretGroup:
    """
    Test Class for delete_secret_group
    """

    @responses.activate
    def test_delete_secret_group_all_params(self):
        """
        delete_secret_group()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'

        # Invoke method
        response = _service.delete_secret_group(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_secret_group_all_params_with_retries(self):
        # Enable retries and run test_delete_secret_group_all_params.
        _service.enable_retries()
        self.test_delete_secret_group_all_params()

        # Disable retries and run test_delete_secret_group_all_params.
        _service.disable_retries()
        self.test_delete_secret_group_all_params()

    @responses.activate
    def test_delete_secret_group_value_error(self):
        """
        test_delete_secret_group_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/d898bb90-82f6-4d61-b5cc-b079b66cfa76')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = 'd898bb90-82f6-4d61-b5cc-b079b66cfa76'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_group(**req_copy)

    def test_delete_secret_group_value_error_with_retries(self):
        # Enable retries and run test_delete_secret_group_value_error.
        _service.enable_retries()
        self.test_delete_secret_group_value_error()

        # Disable retries and run test_delete_secret_group_value_error.
        _service.disable_retries()
        self.test_delete_secret_group_value_error()


# endregion
##############################################################################
# End of Service: SecretGroups
##############################################################################

##############################################################################
# Start of Service: Secrets
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateSecret:
    """
    Test Class for create_secret
    """

    @responses.activate
    def test_create_secret_all_params(self):
        """
        create_secret()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a ArbitrarySecretPrototype model
        secret_prototype_model = {}
        secret_prototype_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_prototype_model['description'] = 'Description of my arbitrary secret.'
        secret_prototype_model['expiration_date'] = '2030-10-05T11:49:42Z'
        secret_prototype_model['labels'] = ['dev', 'us-south']
        secret_prototype_model['name'] = 'example-arbitrary-secret'
        secret_prototype_model['secret_group_id'] = 'default'
        secret_prototype_model['secret_type'] = 'arbitrary'
        secret_prototype_model['payload'] = 'secret-data'
        secret_prototype_model['version_custom_metadata'] = {'custom_version_key': 'custom_version_value'}

        # Set up parameter values
        secret_prototype = secret_prototype_model

        # Invoke method
        response = _service.create_secret(
            secret_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_prototype

    def test_create_secret_all_params_with_retries(self):
        # Enable retries and run test_create_secret_all_params.
        _service.enable_retries()
        self.test_create_secret_all_params()

        # Disable retries and run test_create_secret_all_params.
        _service.disable_retries()
        self.test_create_secret_all_params()

    @responses.activate
    def test_create_secret_value_error(self):
        """
        test_create_secret_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a ArbitrarySecretPrototype model
        secret_prototype_model = {}
        secret_prototype_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_prototype_model['description'] = 'Description of my arbitrary secret.'
        secret_prototype_model['expiration_date'] = '2030-10-05T11:49:42Z'
        secret_prototype_model['labels'] = ['dev', 'us-south']
        secret_prototype_model['name'] = 'example-arbitrary-secret'
        secret_prototype_model['secret_group_id'] = 'default'
        secret_prototype_model['secret_type'] = 'arbitrary'
        secret_prototype_model['payload'] = 'secret-data'
        secret_prototype_model['version_custom_metadata'] = {'custom_version_key': 'custom_version_value'}

        # Set up parameter values
        secret_prototype = secret_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_prototype": secret_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret(**req_copy)

    def test_create_secret_value_error_with_retries(self):
        # Enable retries and run test_create_secret_value_error.
        _service.enable_retries()
        self.test_create_secret_value_error()

        # Disable retries and run test_create_secret_value_error.
        _service.disable_retries()
        self.test_create_secret_value_error()


class TestListSecrets:
    """
    Test Class for list_secrets
    """

    @responses.activate
    def test_list_secrets_all_params(self):
        """
        list_secrets()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "secrets": [{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        offset = 0
        limit = 200
        sort = 'created_at'
        search = 'example'
        groups = ['default', 'cac40995-c37a-4dcb-9506-472869077634']
        secret_types = ['arbitrary', 'kv']
        match_all_labels = ['dev', 'us-south']

        # Invoke method
        response = _service.list_secrets(
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            groups=groups,
            secret_types=secret_types,
            match_all_labels=match_all_labels,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'offset={}'.format(offset) in query_string
        assert 'limit={}'.format(limit) in query_string
        assert 'sort={}'.format(sort) in query_string
        assert 'search={}'.format(search) in query_string
        assert 'groups={}'.format(','.join(groups)) in query_string
        assert 'secret_types={}'.format(','.join(secret_types)) in query_string
        assert 'match_all_labels={}'.format(','.join(match_all_labels)) in query_string

    def test_list_secrets_all_params_with_retries(self):
        # Enable retries and run test_list_secrets_all_params.
        _service.enable_retries()
        self.test_list_secrets_all_params()

        # Disable retries and run test_list_secrets_all_params.
        _service.disable_retries()
        self.test_list_secrets_all_params()

    @responses.activate
    def test_list_secrets_required_params(self):
        """
        test_list_secrets_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "secrets": [{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.list_secrets()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secrets_required_params_with_retries(self):
        # Enable retries and run test_list_secrets_required_params.
        _service.enable_retries()
        self.test_list_secrets_required_params()

        # Disable retries and run test_list_secrets_required_params.
        _service.disable_retries()
        self.test_list_secrets_required_params()

    @responses.activate
    def test_list_secrets_with_pager_get_next(self):
        """
        test_list_secrets_with_pager_get_next()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"arbitrary","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"referenced_by":["my-example-engine-config"],"expiration_date":"2033-04-12T23:20:50.520Z"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"arbitrary","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"referenced_by":["my-example-engine-config"],"expiration_date":"2033-04-12T23:20:50.520Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        all_results = []
        pager = SecretsPager(
            client=_service,
            limit=10,
            sort='created_at',
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            secret_types=['arbitrary', 'kv'],
            match_all_labels=['dev', 'us-south'],
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)
        assert len(all_results) == 2

    @responses.activate
    def test_list_secrets_with_pager_get_all(self):
        """
        test_list_secrets_with_pager_get_all()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"arbitrary","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"referenced_by":["my-example-engine-config"],"expiration_date":"2033-04-12T23:20:50.520Z"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"secrets":[{"created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","crn":"crn","custom_metadata":{"anyKey":"anyValue"},"description":"Extended description for this secret.","downloaded":true,"id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","labels":["my-label"],"locks_total":0,"name":"my-secret","secret_group_id":"default","secret_type":"arbitrary","state":0,"state_description":"active","updated_at":"2022-04-12T23:20:50.520Z","versions_total":0,"referenced_by":["my-example-engine-config"],"expiration_date":"2033-04-12T23:20:50.520Z"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        pager = SecretsPager(
            client=_service,
            limit=10,
            sort='created_at',
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            secret_types=['arbitrary', 'kv'],
            match_all_labels=['dev', 'us-south'],
        )
        all_results = pager.get_all()
        assert all_results is not None
        assert len(all_results) == 2


class TestGetSecret:
    """
    Test Class for get_secret
    """

    @responses.activate
    def test_get_secret_all_params(self):
        """
        get_secret()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.get_secret(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_all_params_with_retries(self):
        # Enable retries and run test_get_secret_all_params.
        _service.enable_retries()
        self.test_get_secret_all_params()

        # Disable retries and run test_get_secret_all_params.
        _service.disable_retries()
        self.test_get_secret_all_params()

    @responses.activate
    def test_get_secret_value_error(self):
        """
        test_get_secret_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret(**req_copy)

    def test_get_secret_value_error_with_retries(self):
        # Enable retries and run test_get_secret_value_error.
        _service.enable_retries()
        self.test_get_secret_value_error()

        # Disable retries and run test_get_secret_value_error.
        _service.disable_retries()
        self.test_get_secret_value_error()


class TestDeleteSecret:
    """
    Test Class for delete_secret
    """

    @responses.activate
    def test_delete_secret_all_params(self):
        """
        delete_secret()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.delete_secret(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_secret_all_params_with_retries(self):
        # Enable retries and run test_delete_secret_all_params.
        _service.enable_retries()
        self.test_delete_secret_all_params()

        # Disable retries and run test_delete_secret_all_params.
        _service.disable_retries()
        self.test_delete_secret_all_params()

    @responses.activate
    def test_delete_secret_value_error(self):
        """
        test_delete_secret_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret(**req_copy)

    def test_delete_secret_value_error_with_retries(self):
        # Enable retries and run test_delete_secret_value_error.
        _service.enable_retries()
        self.test_delete_secret_value_error()

        # Disable retries and run test_delete_secret_value_error.
        _service.disable_retries()
        self.test_delete_secret_value_error()


class TestGetSecretMetadata:
    """
    Test Class for get_secret_metadata
    """

    @responses.activate
    def test_get_secret_metadata_all_params(self):
        """
        get_secret_metadata()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.get_secret_metadata(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_metadata_all_params_with_retries(self):
        # Enable retries and run test_get_secret_metadata_all_params.
        _service.enable_retries()
        self.test_get_secret_metadata_all_params()

        # Disable retries and run test_get_secret_metadata_all_params.
        _service.disable_retries()
        self.test_get_secret_metadata_all_params()

    @responses.activate
    def test_get_secret_metadata_value_error(self):
        """
        test_get_secret_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_metadata(**req_copy)

    def test_get_secret_metadata_value_error_with_retries(self):
        # Enable retries and run test_get_secret_metadata_value_error.
        _service.enable_retries()
        self.test_get_secret_metadata_value_error()

        # Disable retries and run test_get_secret_metadata_value_error.
        _service.disable_retries()
        self.test_get_secret_metadata_value_error()


class TestUpdateSecretMetadata:
    """
    Test Class for update_secret_metadata
    """

    @responses.activate
    def test_update_secret_metadata_all_params(self):
        """
        update_secret_metadata()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a ArbitrarySecretMetadataPatch model
        secret_metadata_patch_model = {}
        secret_metadata_patch_model['name'] = 'updated-arbitrary-secret-name-example'
        secret_metadata_patch_model['description'] = 'updated Arbitrary Secret description'
        secret_metadata_patch_model['labels'] = ['dev', 'us-south']
        secret_metadata_patch_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_metadata_patch_model['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_metadata_patch = secret_metadata_patch_model

        # Invoke method
        response = _service.update_secret_metadata(
            id,
            secret_metadata_patch,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_metadata_patch

    def test_update_secret_metadata_all_params_with_retries(self):
        # Enable retries and run test_update_secret_metadata_all_params.
        _service.enable_retries()
        self.test_update_secret_metadata_all_params()

        # Disable retries and run test_update_secret_metadata_all_params.
        _service.disable_retries()
        self.test_update_secret_metadata_all_params()

    @responses.activate
    def test_update_secret_metadata_value_error(self):
        """
        test_update_secret_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/metadata')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a ArbitrarySecretMetadataPatch model
        secret_metadata_patch_model = {}
        secret_metadata_patch_model['name'] = 'updated-arbitrary-secret-name-example'
        secret_metadata_patch_model['description'] = 'updated Arbitrary Secret description'
        secret_metadata_patch_model['labels'] = ['dev', 'us-south']
        secret_metadata_patch_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_metadata_patch_model['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_metadata_patch = secret_metadata_patch_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "secret_metadata_patch": secret_metadata_patch,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_metadata(**req_copy)

    def test_update_secret_metadata_value_error_with_retries(self):
        # Enable retries and run test_update_secret_metadata_value_error.
        _service.enable_retries()
        self.test_update_secret_metadata_value_error()

        # Disable retries and run test_update_secret_metadata_value_error.
        _service.disable_retries()
        self.test_update_secret_metadata_value_error()


class TestCreateSecretAction:
    """
    Test Class for create_secret_action
    """

    @responses.activate
    def test_create_secret_action_all_params(self):
        """
        create_secret_action()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/actions')
        mock_response = '{"action_type": "public_cert_action_validate_dns_challenge"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateActionRevokePrototype model
        secret_action_prototype_model = {}
        secret_action_prototype_model['action_type'] = 'private_cert_action_revoke_certificate'

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_action_prototype = secret_action_prototype_model

        # Invoke method
        response = _service.create_secret_action(
            id,
            secret_action_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_action_prototype

    def test_create_secret_action_all_params_with_retries(self):
        # Enable retries and run test_create_secret_action_all_params.
        _service.enable_retries()
        self.test_create_secret_action_all_params()

        # Disable retries and run test_create_secret_action_all_params.
        _service.disable_retries()
        self.test_create_secret_action_all_params()

    @responses.activate
    def test_create_secret_action_value_error(self):
        """
        test_create_secret_action_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/actions')
        mock_response = '{"action_type": "public_cert_action_validate_dns_challenge"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateActionRevokePrototype model
        secret_action_prototype_model = {}
        secret_action_prototype_model['action_type'] = 'private_cert_action_revoke_certificate'

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_action_prototype = secret_action_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "secret_action_prototype": secret_action_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_action(**req_copy)

    def test_create_secret_action_value_error_with_retries(self):
        # Enable retries and run test_create_secret_action_value_error.
        _service.enable_retries()
        self.test_create_secret_action_value_error()

        # Disable retries and run test_create_secret_action_value_error.
        _service.disable_retries()
        self.test_create_secret_action_value_error()


class TestGetSecretByNameType:
    """
    Test Class for get_secret_by_name_type
    """

    @responses.activate
    def test_get_secret_by_name_type_all_params(self):
        """
        get_secret_by_name_type()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/default/secret_types/arbitrary/secrets/my-secret')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_type = 'arbitrary'
        name = 'my-secret'
        secret_group_name = 'default'

        # Invoke method
        response = _service.get_secret_by_name_type(
            secret_type,
            name,
            secret_group_name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_by_name_type_all_params_with_retries(self):
        # Enable retries and run test_get_secret_by_name_type_all_params.
        _service.enable_retries()
        self.test_get_secret_by_name_type_all_params()

        # Disable retries and run test_get_secret_by_name_type_all_params.
        _service.disable_retries()
        self.test_get_secret_by_name_type_all_params()

    @responses.activate
    def test_get_secret_by_name_type_value_error(self):
        """
        test_get_secret_by_name_type_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secret_groups/default/secret_types/arbitrary/secrets/my-secret')
        mock_response = '{"created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "crn": "crn", "custom_metadata": {"anyKey": "anyValue"}, "description": "Extended description for this secret.", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "labels": ["my-label"], "locks_total": 0, "name": "my-secret", "secret_group_id": "default", "secret_type": "arbitrary", "state": 0, "state_description": "active", "updated_at": "2022-04-12T23:20:50.520Z", "versions_total": 0, "referenced_by": ["my-example-engine-config"], "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_type = 'arbitrary'
        name = 'my-secret'
        secret_group_name = 'default'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "name": name,
            "secret_group_name": secret_group_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_by_name_type(**req_copy)

    def test_get_secret_by_name_type_value_error_with_retries(self):
        # Enable retries and run test_get_secret_by_name_type_value_error.
        _service.enable_retries()
        self.test_get_secret_by_name_type_value_error()

        # Disable retries and run test_get_secret_by_name_type_value_error.
        _service.disable_retries()
        self.test_get_secret_by_name_type_value_error()


# endregion
##############################################################################
# End of Service: Secrets
##############################################################################

##############################################################################
# Start of Service: SecretVersions
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateSecretVersion:
    """
    Test Class for create_secret_version
    """

    @responses.activate
    def test_create_secret_version_all_params(self):
        """
        create_secret_version()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a ArbitrarySecretVersionPrototype model
        secret_version_prototype_model = {}
        secret_version_prototype_model['payload'] = 'updated secret credentials'
        secret_version_prototype_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_version_prototype_model['version_custom_metadata'] = {'custom_version_key': 'custom_version_value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_version_prototype = secret_version_prototype_model

        # Invoke method
        response = _service.create_secret_version(
            secret_id,
            secret_version_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_version_prototype

    def test_create_secret_version_all_params_with_retries(self):
        # Enable retries and run test_create_secret_version_all_params.
        _service.enable_retries()
        self.test_create_secret_version_all_params()

        # Disable retries and run test_create_secret_version_all_params.
        _service.disable_retries()
        self.test_create_secret_version_all_params()

    @responses.activate
    def test_create_secret_version_value_error(self):
        """
        test_create_secret_version_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a ArbitrarySecretVersionPrototype model
        secret_version_prototype_model = {}
        secret_version_prototype_model['payload'] = 'updated secret credentials'
        secret_version_prototype_model['custom_metadata'] = {'metadata_custom_key': 'metadata_custom_value'}
        secret_version_prototype_model['version_custom_metadata'] = {'custom_version_key': 'custom_version_value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        secret_version_prototype = secret_version_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "secret_version_prototype": secret_version_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_version(**req_copy)

    def test_create_secret_version_value_error_with_retries(self):
        # Enable retries and run test_create_secret_version_value_error.
        _service.enable_retries()
        self.test_create_secret_version_value_error()

        # Disable retries and run test_create_secret_version_value_error.
        _service.disable_retries()
        self.test_create_secret_version_value_error()


class TestListSecretVersions:
    """
    Test Class for list_secret_versions
    """

    @responses.activate
    def test_list_secret_versions_all_params(self):
        """
        list_secret_versions()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions')
        mock_response = '{"versions": [{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}], "total_count": 0}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.list_secret_versions(
            secret_id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secret_versions_all_params_with_retries(self):
        # Enable retries and run test_list_secret_versions_all_params.
        _service.enable_retries()
        self.test_list_secret_versions_all_params()

        # Disable retries and run test_list_secret_versions_all_params.
        _service.disable_retries()
        self.test_list_secret_versions_all_params()

    @responses.activate
    def test_list_secret_versions_value_error(self):
        """
        test_list_secret_versions_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions')
        mock_response = '{"versions": [{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}], "total_count": 0}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.list_secret_versions(**req_copy)

    def test_list_secret_versions_value_error_with_retries(self):
        # Enable retries and run test_list_secret_versions_value_error.
        _service.enable_retries()
        self.test_list_secret_versions_value_error()

        # Disable retries and run test_list_secret_versions_value_error.
        _service.disable_retries()
        self.test_list_secret_versions_value_error()


class TestGetSecretVersion:
    """
    Test Class for get_secret_version
    """

    @responses.activate
    def test_get_secret_version_all_params(self):
        """
        get_secret_version()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Invoke method
        response = _service.get_secret_version(
            secret_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_version_all_params_with_retries(self):
        # Enable retries and run test_get_secret_version_all_params.
        _service.enable_retries()
        self.test_get_secret_version_all_params()

        # Disable retries and run test_get_secret_version_all_params.
        _service.disable_retries()
        self.test_get_secret_version_all_params()

    @responses.activate
    def test_get_secret_version_value_error(self):
        """
        test_get_secret_version_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z", "payload": "secret-credentials"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_version(**req_copy)

    def test_get_secret_version_value_error_with_retries(self):
        # Enable retries and run test_get_secret_version_value_error.
        _service.enable_retries()
        self.test_get_secret_version_value_error()

        # Disable retries and run test_get_secret_version_value_error.
        _service.disable_retries()
        self.test_get_secret_version_value_error()


class TestDeleteSecretVersionData:
    """
    Test Class for delete_secret_version_data
    """

    @responses.activate
    def test_delete_secret_version_data_all_params(self):
        """
        delete_secret_version_data()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/secret_data')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Invoke method
        response = _service.delete_secret_version_data(
            secret_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_secret_version_data_all_params_with_retries(self):
        # Enable retries and run test_delete_secret_version_data_all_params.
        _service.enable_retries()
        self.test_delete_secret_version_data_all_params()

        # Disable retries and run test_delete_secret_version_data_all_params.
        _service.disable_retries()
        self.test_delete_secret_version_data_all_params()

    @responses.activate
    def test_delete_secret_version_data_value_error(self):
        """
        test_delete_secret_version_data_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/secret_data')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_version_data(**req_copy)

    def test_delete_secret_version_data_value_error_with_retries(self):
        # Enable retries and run test_delete_secret_version_data_value_error.
        _service.enable_retries()
        self.test_delete_secret_version_data_value_error()

        # Disable retries and run test_delete_secret_version_data_value_error.
        _service.disable_retries()
        self.test_delete_secret_version_data_value_error()


class TestGetSecretVersionMetadata:
    """
    Test Class for get_secret_version_metadata
    """

    @responses.activate
    def test_get_secret_version_metadata_all_params(self):
        """
        get_secret_version_metadata()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Invoke method
        response = _service.get_secret_version_metadata(
            secret_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_secret_version_metadata_all_params_with_retries(self):
        # Enable retries and run test_get_secret_version_metadata_all_params.
        _service.enable_retries()
        self.test_get_secret_version_metadata_all_params()

        # Disable retries and run test_get_secret_version_metadata_all_params.
        _service.disable_retries()
        self.test_get_secret_version_metadata_all_params()

    @responses.activate
    def test_get_secret_version_metadata_value_error(self):
        """
        test_get_secret_version_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_version_metadata(**req_copy)

    def test_get_secret_version_metadata_value_error_with_retries(self):
        # Enable retries and run test_get_secret_version_metadata_value_error.
        _service.enable_retries()
        self.test_get_secret_version_metadata_value_error()

        # Disable retries and run test_get_secret_version_metadata_value_error.
        _service.disable_retries()
        self.test_get_secret_version_metadata_value_error()


class TestUpdateSecretVersionMetadata:
    """
    Test Class for update_secret_version_metadata
    """

    @responses.activate
    def test_update_secret_version_metadata_all_params(self):
        """
        update_secret_version_metadata()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a SecretVersionMetadataPatch model
        secret_version_metadata_patch_model = {}
        secret_version_metadata_patch_model['version_custom_metadata'] = {'key': 'value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        secret_version_metadata_patch = secret_version_metadata_patch_model

        # Invoke method
        response = _service.update_secret_version_metadata(
            secret_id,
            id,
            secret_version_metadata_patch,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_version_metadata_patch

    def test_update_secret_version_metadata_all_params_with_retries(self):
        # Enable retries and run test_update_secret_version_metadata_all_params.
        _service.enable_retries()
        self.test_update_secret_version_metadata_all_params()

        # Disable retries and run test_update_secret_version_metadata_all_params.
        _service.disable_retries()
        self.test_update_secret_version_metadata_all_params()

    @responses.activate
    def test_update_secret_version_metadata_value_error(self):
        """
        test_update_secret_version_metadata_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/metadata')
        mock_response = '{"auto_rotated": true, "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "downloaded": true, "id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_name": "my-secret", "secret_type": "arbitrary", "secret_group_id": "default", "payload_available": false, "alias": "current", "version_custom_metadata": {"anyKey": "anyValue"}, "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "expiration_date": "2033-04-12T23:20:50.520Z"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a SecretVersionMetadataPatch model
        secret_version_metadata_patch_model = {}
        secret_version_metadata_patch_model['version_custom_metadata'] = {'key': 'value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        secret_version_metadata_patch = secret_version_metadata_patch_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
            "secret_version_metadata_patch": secret_version_metadata_patch,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_version_metadata(**req_copy)

    def test_update_secret_version_metadata_value_error_with_retries(self):
        # Enable retries and run test_update_secret_version_metadata_value_error.
        _service.enable_retries()
        self.test_update_secret_version_metadata_value_error()

        # Disable retries and run test_update_secret_version_metadata_value_error.
        _service.disable_retries()
        self.test_update_secret_version_metadata_value_error()


class TestCreateSecretVersionAction:
    """
    Test Class for create_secret_version_action
    """

    @responses.activate
    def test_create_secret_version_action_all_params(self):
        """
        create_secret_version_action()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/actions')
        mock_response = '{"action_type": "private_cert_action_revoke_certificate", "revocation_time_seconds": 1577836800}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateVersionActionRevokePrototype model
        secret_version_action_prototype_model = {}
        secret_version_action_prototype_model['action_type'] = 'private_cert_action_revoke_certificate'

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        secret_version_action_prototype = secret_version_action_prototype_model

        # Invoke method
        response = _service.create_secret_version_action(
            secret_id,
            id,
            secret_version_action_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_version_action_prototype

    def test_create_secret_version_action_all_params_with_retries(self):
        # Enable retries and run test_create_secret_version_action_all_params.
        _service.enable_retries()
        self.test_create_secret_version_action_all_params()

        # Disable retries and run test_create_secret_version_action_all_params.
        _service.disable_retries()
        self.test_create_secret_version_action_all_params()

    @responses.activate
    def test_create_secret_version_action_value_error(self):
        """
        test_create_secret_version_action_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/actions')
        mock_response = '{"action_type": "private_cert_action_revoke_certificate", "revocation_time_seconds": 1577836800}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateVersionActionRevokePrototype model
        secret_version_action_prototype_model = {}
        secret_version_action_prototype_model['action_type'] = 'private_cert_action_revoke_certificate'

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        secret_version_action_prototype = secret_version_action_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
            "secret_version_action_prototype": secret_version_action_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_version_action(**req_copy)

    def test_create_secret_version_action_value_error_with_retries(self):
        # Enable retries and run test_create_secret_version_action_value_error.
        _service.enable_retries()
        self.test_create_secret_version_action_value_error()

        # Disable retries and run test_create_secret_version_action_value_error.
        _service.disable_retries()
        self.test_create_secret_version_action_value_error()


# endregion
##############################################################################
# End of Service: SecretVersions
##############################################################################

##############################################################################
# Start of Service: SecretLocks
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestListSecretsLocks:
    """
    Test Class for list_secrets_locks
    """

    @responses.activate
    def test_list_secrets_locks_all_params(self):
        """
        list_secrets_locks()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets_locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "secrets_locks": [{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        offset = 0
        limit = 200
        search = 'example'
        groups = ['default', 'cac40995-c37a-4dcb-9506-472869077634']

        # Invoke method
        response = _service.list_secrets_locks(
            offset=offset,
            limit=limit,
            search=search,
            groups=groups,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'offset={}'.format(offset) in query_string
        assert 'limit={}'.format(limit) in query_string
        assert 'search={}'.format(search) in query_string
        assert 'groups={}'.format(','.join(groups)) in query_string

    def test_list_secrets_locks_all_params_with_retries(self):
        # Enable retries and run test_list_secrets_locks_all_params.
        _service.enable_retries()
        self.test_list_secrets_locks_all_params()

        # Disable retries and run test_list_secrets_locks_all_params.
        _service.disable_retries()
        self.test_list_secrets_locks_all_params()

    @responses.activate
    def test_list_secrets_locks_required_params(self):
        """
        test_list_secrets_locks_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets_locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "secrets_locks": [{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.list_secrets_locks()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secrets_locks_required_params_with_retries(self):
        # Enable retries and run test_list_secrets_locks_required_params.
        _service.enable_retries()
        self.test_list_secrets_locks_required_params()

        # Disable retries and run test_list_secrets_locks_required_params.
        _service.disable_retries()
        self.test_list_secrets_locks_required_params()

    @responses.activate
    def test_list_secrets_locks_with_pager_get_next(self):
        """
        test_list_secrets_locks_with_pager_get_next()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets_locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":false}]}],"total_count":2,"limit":1}'
        mock_response2 = '{"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":false}]}],"total_count":2,"limit":1}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        all_results = []
        pager = SecretsLocksPager(
            client=_service,
            limit=10,
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)
        assert len(all_results) == 2

    @responses.activate
    def test_list_secrets_locks_with_pager_get_all(self):
        """
        test_list_secrets_locks_with_pager_get_all()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets_locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":false}]}],"total_count":2,"limit":1}'
        mock_response2 = '{"secrets_locks":[{"secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_group_id":"default","secret_type":"arbitrary","secret_name":"my-secret","versions":[{"version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","version_alias":"current","locks":["lock-example"],"payload_available":false}]}],"total_count":2,"limit":1}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        pager = SecretsLocksPager(
            client=_service,
            limit=10,
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
        )
        all_results = pager.get_all()
        assert all_results is not None
        assert len(all_results) == 2


class TestListSecretLocks:
    """
    Test Class for list_secret_locks
    """

    @responses.activate
    def test_list_secret_locks_all_params(self):
        """
        list_secret_locks()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        offset = 0
        limit = 25
        sort = 'name'
        search = 'example'

        # Invoke method
        response = _service.list_secret_locks(
            id,
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'offset={}'.format(offset) in query_string
        assert 'limit={}'.format(limit) in query_string
        assert 'sort={}'.format(sort) in query_string
        assert 'search={}'.format(search) in query_string

    def test_list_secret_locks_all_params_with_retries(self):
        # Enable retries and run test_list_secret_locks_all_params.
        _service.enable_retries()
        self.test_list_secret_locks_all_params()

        # Disable retries and run test_list_secret_locks_all_params.
        _service.disable_retries()
        self.test_list_secret_locks_all_params()

    @responses.activate
    def test_list_secret_locks_required_params(self):
        """
        test_list_secret_locks_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.list_secret_locks(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secret_locks_required_params_with_retries(self):
        # Enable retries and run test_list_secret_locks_required_params.
        _service.enable_retries()
        self.test_list_secret_locks_required_params()

        # Disable retries and run test_list_secret_locks_required_params.
        _service.disable_retries()
        self.test_list_secret_locks_required_params()

    @responses.activate
    def test_list_secret_locks_value_error(self):
        """
        test_list_secret_locks_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.list_secret_locks(**req_copy)

    def test_list_secret_locks_value_error_with_retries(self):
        # Enable retries and run test_list_secret_locks_value_error.
        _service.enable_retries()
        self.test_list_secret_locks_value_error()

        # Disable retries and run test_list_secret_locks_value_error.
        _service.disable_retries()
        self.test_list_secret_locks_value_error()

    @responses.activate
    def test_list_secret_locks_with_pager_get_next(self):
        """
        test_list_secret_locks_with_pager_get_next()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        all_results = []
        pager = SecretLocksPager(
            client=_service,
            id='0b5571f7-21e6-42b7-91c5-3f5ac9793a46',
            limit=10,
            sort='name',
            search='example',
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)
        assert len(all_results) == 2

    @responses.activate
    def test_list_secret_locks_with_pager_get_all(self):
        """
        test_list_secret_locks_with_pager_get_all()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        pager = SecretLocksPager(
            client=_service,
            id='0b5571f7-21e6-42b7-91c5-3f5ac9793a46',
            limit=10,
            sort='name',
            search='example',
        )
        all_results = pager.get_all()
        assert all_results is not None
        assert len(all_results) == 2


class TestCreateSecretLocksBulk:
    """
    Test Class for create_secret_locks_bulk
    """

    @responses.activate
    def test_create_secret_locks_bulk_all_params(self):
        """
        create_secret_locks_bulk()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        locks = [secret_lock_prototype_model]
        mode = 'remove_previous'

        # Invoke method
        response = _service.create_secret_locks_bulk(
            id,
            locks,
            mode=mode,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'mode={}'.format(mode) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['locks'] == [secret_lock_prototype_model]

    def test_create_secret_locks_bulk_all_params_with_retries(self):
        # Enable retries and run test_create_secret_locks_bulk_all_params.
        _service.enable_retries()
        self.test_create_secret_locks_bulk_all_params()

        # Disable retries and run test_create_secret_locks_bulk_all_params.
        _service.disable_retries()
        self.test_create_secret_locks_bulk_all_params()

    @responses.activate
    def test_create_secret_locks_bulk_required_params(self):
        """
        test_create_secret_locks_bulk_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        locks = [secret_lock_prototype_model]

        # Invoke method
        response = _service.create_secret_locks_bulk(
            id,
            locks,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['locks'] == [secret_lock_prototype_model]

    def test_create_secret_locks_bulk_required_params_with_retries(self):
        # Enable retries and run test_create_secret_locks_bulk_required_params.
        _service.enable_retries()
        self.test_create_secret_locks_bulk_required_params()

        # Disable retries and run test_create_secret_locks_bulk_required_params.
        _service.disable_retries()
        self.test_create_secret_locks_bulk_required_params()

    @responses.activate
    def test_create_secret_locks_bulk_value_error(self):
        """
        test_create_secret_locks_bulk_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        locks = [secret_lock_prototype_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "locks": locks,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_locks_bulk(**req_copy)

    def test_create_secret_locks_bulk_value_error_with_retries(self):
        # Enable retries and run test_create_secret_locks_bulk_value_error.
        _service.enable_retries()
        self.test_create_secret_locks_bulk_value_error()

        # Disable retries and run test_create_secret_locks_bulk_value_error.
        _service.disable_retries()
        self.test_create_secret_locks_bulk_value_error()


class TestDeleteSecretLocksBulk:
    """
    Test Class for delete_secret_locks_bulk
    """

    @responses.activate
    def test_delete_secret_locks_bulk_all_params(self):
        """
        delete_secret_locks_bulk()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        name = ['lock-example-1']

        # Invoke method
        response = _service.delete_secret_locks_bulk(
            id,
            name=name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'name={}'.format(','.join(name)) in query_string

    def test_delete_secret_locks_bulk_all_params_with_retries(self):
        # Enable retries and run test_delete_secret_locks_bulk_all_params.
        _service.enable_retries()
        self.test_delete_secret_locks_bulk_all_params()

        # Disable retries and run test_delete_secret_locks_bulk_all_params.
        _service.disable_retries()
        self.test_delete_secret_locks_bulk_all_params()

    @responses.activate
    def test_delete_secret_locks_bulk_required_params(self):
        """
        test_delete_secret_locks_bulk_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Invoke method
        response = _service.delete_secret_locks_bulk(
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_delete_secret_locks_bulk_required_params_with_retries(self):
        # Enable retries and run test_delete_secret_locks_bulk_required_params.
        _service.enable_retries()
        self.test_delete_secret_locks_bulk_required_params()

        # Disable retries and run test_delete_secret_locks_bulk_required_params.
        _service.disable_retries()
        self.test_delete_secret_locks_bulk_required_params()

    @responses.activate
    def test_delete_secret_locks_bulk_value_error(self):
        """
        test_delete_secret_locks_bulk_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_locks_bulk(**req_copy)

    def test_delete_secret_locks_bulk_value_error_with_retries(self):
        # Enable retries and run test_delete_secret_locks_bulk_value_error.
        _service.enable_retries()
        self.test_delete_secret_locks_bulk_value_error()

        # Disable retries and run test_delete_secret_locks_bulk_value_error.
        _service.disable_retries()
        self.test_delete_secret_locks_bulk_value_error()


class TestListSecretVersionLocks:
    """
    Test Class for list_secret_version_locks
    """

    @responses.activate
    def test_list_secret_version_locks_all_params(self):
        """
        list_secret_version_locks()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        offset = 0
        limit = 25
        sort = 'name'
        search = 'example'

        # Invoke method
        response = _service.list_secret_version_locks(
            secret_id,
            id,
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'offset={}'.format(offset) in query_string
        assert 'limit={}'.format(limit) in query_string
        assert 'sort={}'.format(sort) in query_string
        assert 'search={}'.format(search) in query_string

    def test_list_secret_version_locks_all_params_with_retries(self):
        # Enable retries and run test_list_secret_version_locks_all_params.
        _service.enable_retries()
        self.test_list_secret_version_locks_all_params()

        # Disable retries and run test_list_secret_version_locks_all_params.
        _service.disable_retries()
        self.test_list_secret_version_locks_all_params()

    @responses.activate
    def test_list_secret_version_locks_required_params(self):
        """
        test_list_secret_version_locks_required_params()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Invoke method
        response = _service.list_secret_version_locks(
            secret_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_secret_version_locks_required_params_with_retries(self):
        # Enable retries and run test_list_secret_version_locks_required_params.
        _service.enable_retries()
        self.test_list_secret_version_locks_required_params()

        # Disable retries and run test_list_secret_version_locks_required_params.
        _service.disable_retries()
        self.test_list_secret_version_locks_required_params()

    @responses.activate
    def test_list_secret_version_locks_value_error(self):
        """
        test_list_secret_version_locks_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "locks": [{"name": "lock-example", "description": "description", "attributes": {"anyKey": "anyValue"}, "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "secret_group_id": "default", "secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_version_alias": "current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.list_secret_version_locks(**req_copy)

    def test_list_secret_version_locks_value_error_with_retries(self):
        # Enable retries and run test_list_secret_version_locks_value_error.
        _service.enable_retries()
        self.test_list_secret_version_locks_value_error()

        # Disable retries and run test_list_secret_version_locks_value_error.
        _service.disable_retries()
        self.test_list_secret_version_locks_value_error()

    @responses.activate
    def test_list_secret_version_locks_with_pager_get_next(self):
        """
        test_list_secret_version_locks_with_pager_get_next()
        """
        # Set up a two-page mock response
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        all_results = []
        pager = SecretVersionLocksPager(
            client=_service,
            secret_id='0b5571f7-21e6-42b7-91c5-3f5ac9793a46',
            id='eb4cf24d-9cae-424b-945e-159788a5f535',
            limit=10,
            sort='name',
            search='example',
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)
        assert len(all_results) == 2

    @responses.activate
    def test_list_secret_version_locks_with_pager_get_all(self):
        """
        test_list_secret_version_locks_with_pager_get_all()
        """
        # Set up a two-page mock response
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        mock_response2 = '{"total_count":2,"limit":1,"locks":[{"name":"lock-example","description":"description","attributes":{"anyKey":"anyValue"},"created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","secret_group_id":"default","secret_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_id":"b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5","secret_version_alias":"current"}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        pager = SecretVersionLocksPager(
            client=_service,
            secret_id='0b5571f7-21e6-42b7-91c5-3f5ac9793a46',
            id='eb4cf24d-9cae-424b-945e-159788a5f535',
            limit=10,
            sort='name',
            search='example',
        )
        all_results = pager.get_all()
        assert all_results is not None
        assert len(all_results) == 2


class TestCreateSecretVersionLocksBulk:
    """
    Test Class for create_secret_version_locks_bulk
    """

    @responses.activate
    def test_create_secret_version_locks_bulk_all_params(self):
        """
        create_secret_version_locks_bulk()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        locks = [secret_lock_prototype_model]
        mode = 'remove_previous'

        # Invoke method
        response = _service.create_secret_version_locks_bulk(
            secret_id,
            id,
            locks,
            mode=mode,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'mode={}'.format(mode) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['locks'] == [secret_lock_prototype_model]

    def test_create_secret_version_locks_bulk_all_params_with_retries(self):
        # Enable retries and run test_create_secret_version_locks_bulk_all_params.
        _service.enable_retries()
        self.test_create_secret_version_locks_bulk_all_params()

        # Disable retries and run test_create_secret_version_locks_bulk_all_params.
        _service.disable_retries()
        self.test_create_secret_version_locks_bulk_all_params()

    @responses.activate
    def test_create_secret_version_locks_bulk_required_params(self):
        """
        test_create_secret_version_locks_bulk_required_params()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        locks = [secret_lock_prototype_model]

        # Invoke method
        response = _service.create_secret_version_locks_bulk(
            secret_id,
            id,
            locks,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['locks'] == [secret_lock_prototype_model]

    def test_create_secret_version_locks_bulk_required_params_with_retries(self):
        # Enable retries and run test_create_secret_version_locks_bulk_required_params.
        _service.enable_retries()
        self.test_create_secret_version_locks_bulk_required_params()

        # Disable retries and run test_create_secret_version_locks_bulk_required_params.
        _service.disable_retries()
        self.test_create_secret_version_locks_bulk_required_params()

    @responses.activate
    def test_create_secret_version_locks_bulk_value_error(self):
        """
        test_create_secret_version_locks_bulk_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {}
        secret_lock_prototype_model['name'] = 'lock-example-1'
        secret_lock_prototype_model['description'] = 'lock for consumer 1'
        secret_lock_prototype_model['attributes'] = {'key': 'value'}

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        locks = [secret_lock_prototype_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
            "locks": locks,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_version_locks_bulk(**req_copy)

    def test_create_secret_version_locks_bulk_value_error_with_retries(self):
        # Enable retries and run test_create_secret_version_locks_bulk_value_error.
        _service.enable_retries()
        self.test_create_secret_version_locks_bulk_value_error()

        # Disable retries and run test_create_secret_version_locks_bulk_value_error.
        _service.disable_retries()
        self.test_create_secret_version_locks_bulk_value_error()


class TestDeleteSecretVersionLocksBulk:
    """
    Test Class for delete_secret_version_locks_bulk
    """

    @responses.activate
    def test_delete_secret_version_locks_bulk_all_params(self):
        """
        delete_secret_version_locks_bulk()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'
        name = ['lock-example-1']

        # Invoke method
        response = _service.delete_secret_version_locks_bulk(
            secret_id,
            id,
            name=name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'name={}'.format(','.join(name)) in query_string

    def test_delete_secret_version_locks_bulk_all_params_with_retries(self):
        # Enable retries and run test_delete_secret_version_locks_bulk_all_params.
        _service.enable_retries()
        self.test_delete_secret_version_locks_bulk_all_params()

        # Disable retries and run test_delete_secret_version_locks_bulk_all_params.
        _service.disable_retries()
        self.test_delete_secret_version_locks_bulk_all_params()

    @responses.activate
    def test_delete_secret_version_locks_bulk_required_params(self):
        """
        test_delete_secret_version_locks_bulk_required_params()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Invoke method
        response = _service.delete_secret_version_locks_bulk(
            secret_id,
            id,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_delete_secret_version_locks_bulk_required_params_with_retries(self):
        # Enable retries and run test_delete_secret_version_locks_bulk_required_params.
        _service.enable_retries()
        self.test_delete_secret_version_locks_bulk_required_params()

        # Disable retries and run test_delete_secret_version_locks_bulk_required_params.
        _service.disable_retries()
        self.test_delete_secret_version_locks_bulk_required_params()

    @responses.activate
    def test_delete_secret_version_locks_bulk_value_error(self):
        """
        test_delete_secret_version_locks_bulk_value_error()
        """
        # Set up mock
        url = preprocess_url(
            '/api/v2/secrets/0b5571f7-21e6-42b7-91c5-3f5ac9793a46/versions/eb4cf24d-9cae-424b-945e-159788a5f535/locks_bulk')
        mock_response = '{"secret_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "secret_group_id": "default", "secret_type": "arbitrary", "secret_name": "my-secret", "versions": [{"version_id": "b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5", "version_alias": "current", "locks": ["lock-example"], "payload_available": false}]}'
        responses.add(
            responses.DELETE,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        secret_id = '0b5571f7-21e6-42b7-91c5-3f5ac9793a46'
        id = 'eb4cf24d-9cae-424b-945e-159788a5f535'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_id": secret_id,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_version_locks_bulk(**req_copy)

    def test_delete_secret_version_locks_bulk_value_error_with_retries(self):
        # Enable retries and run test_delete_secret_version_locks_bulk_value_error.
        _service.enable_retries()
        self.test_delete_secret_version_locks_bulk_value_error()

        # Disable retries and run test_delete_secret_version_locks_bulk_value_error.
        _service.disable_retries()
        self.test_delete_secret_version_locks_bulk_value_error()


# endregion
##############################################################################
# End of Service: SecretLocks
##############################################################################

##############################################################################
# Start of Service: Configurations
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateConfiguration:
    """
    Test Class for create_configuration
    """

    @responses.activate
    def test_create_configuration_all_params(self):
        """
        create_configuration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPrototype model
        configuration_prototype_model = {}
        configuration_prototype_model['config_type'] = 'public_cert_configuration_dns_cloud_internet_services'
        configuration_prototype_model['name'] = 'example-cloud-internet-services-config'
        configuration_prototype_model['cloud_internet_services_apikey'] = '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ'
        configuration_prototype_model[
            'cloud_internet_services_crn'] = 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::'

        # Set up parameter values
        configuration_prototype = configuration_prototype_model

        # Invoke method
        response = _service.create_configuration(
            configuration_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == configuration_prototype

    def test_create_configuration_all_params_with_retries(self):
        # Enable retries and run test_create_configuration_all_params.
        _service.enable_retries()
        self.test_create_configuration_all_params()

        # Disable retries and run test_create_configuration_all_params.
        _service.disable_retries()
        self.test_create_configuration_all_params()

    @responses.activate
    def test_create_configuration_value_error(self):
        """
        test_create_configuration_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPrototype model
        configuration_prototype_model = {}
        configuration_prototype_model['config_type'] = 'public_cert_configuration_dns_cloud_internet_services'
        configuration_prototype_model['name'] = 'example-cloud-internet-services-config'
        configuration_prototype_model['cloud_internet_services_apikey'] = '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ'
        configuration_prototype_model[
            'cloud_internet_services_crn'] = 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::'

        # Set up parameter values
        configuration_prototype = configuration_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "configuration_prototype": configuration_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_configuration(**req_copy)

    def test_create_configuration_value_error_with_retries(self):
        # Enable retries and run test_create_configuration_value_error.
        _service.enable_retries()
        self.test_create_configuration_value_error()

        # Disable retries and run test_create_configuration_value_error.
        _service.disable_retries()
        self.test_create_configuration_value_error()


class TestListConfigurations:
    """
    Test Class for list_configurations
    """

    @responses.activate
    def test_list_configurations_all_params(self):
        """
        list_configurations()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "configurations": [{"config_type": "iam_credentials_configuration", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "disabled": true}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        offset = 0
        limit = 200
        sort = 'config_type'
        search = 'example'
        secret_types = ['iam_credentials', 'public_cert', 'private_cert']

        # Invoke method
        response = _service.list_configurations(
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            secret_types=secret_types,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'offset={}'.format(offset) in query_string
        assert 'limit={}'.format(limit) in query_string
        assert 'sort={}'.format(sort) in query_string
        assert 'search={}'.format(search) in query_string
        assert 'secret_types={}'.format(','.join(secret_types)) in query_string

    def test_list_configurations_all_params_with_retries(self):
        # Enable retries and run test_list_configurations_all_params.
        _service.enable_retries()
        self.test_list_configurations_all_params()

        # Disable retries and run test_list_configurations_all_params.
        _service.disable_retries()
        self.test_list_configurations_all_params()

    @responses.activate
    def test_list_configurations_required_params(self):
        """
        test_list_configurations_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations')
        mock_response = '{"total_count": 0, "limit": 25, "offset": 25, "first": {"href": "href"}, "next": {"href": "href"}, "previous": {"href": "href"}, "last": {"href": "href"}, "configurations": [{"config_type": "iam_credentials_configuration", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "disabled": true}]}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.list_configurations()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_list_configurations_required_params_with_retries(self):
        # Enable retries and run test_list_configurations_required_params.
        _service.enable_retries()
        self.test_list_configurations_required_params()

        # Disable retries and run test_list_configurations_required_params.
        _service.disable_retries()
        self.test_list_configurations_required_params()

    @responses.activate
    def test_list_configurations_with_pager_get_next(self):
        """
        test_list_configurations_with_pager_get_next()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/configurations')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","disabled":true}],"limit":1}'
        mock_response2 = '{"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","disabled":true}],"limit":1}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        all_results = []
        pager = ConfigurationsPager(
            client=_service,
            limit=10,
            sort='config_type',
            search='example',
            secret_types=['iam_credentials', 'public_cert', 'private_cert'],
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)
        assert len(all_results) == 2

    @responses.activate
    def test_list_configurations_with_pager_get_all(self):
        """
        test_list_configurations_with_pager_get_all()
        """
        # Set up a two-page mock response
        url = preprocess_url('/api/v2/configurations')
        mock_response1 = '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","disabled":true}],"limit":1}'
        mock_response2 = '{"total_count":2,"configurations":[{"config_type":"iam_credentials_configuration","name":"my-secret-engine-config","secret_type":"arbitrary","created_by":"iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21","created_at":"2022-04-12T23:20:50.520Z","updated_at":"2022-04-12T23:20:50.520Z","disabled":true}],"limit":1}'
        responses.add(
            responses.GET,
            url,
            body=mock_response1,
            content_type='application/json',
            status=200,
        )
        responses.add(
            responses.GET,
            url,
            body=mock_response2,
            content_type='application/json',
            status=200,
        )

        # Exercise the pager class for this operation
        pager = ConfigurationsPager(
            client=_service,
            limit=10,
            sort='config_type',
            search='example',
            secret_types=['iam_credentials', 'public_cert', 'private_cert'],
        )
        all_results = pager.get_all()
        assert all_results is not None
        assert len(all_results) == 2


class TestGetConfiguration:
    """
    Test Class for get_configuration
    """

    @responses.activate
    def test_get_configuration_all_params(self):
        """
        get_configuration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        name = 'configuration-name'
        x_sm_accept_configuration_type = 'public_cert_configuration_dns_cloud_internet_services'

        # Invoke method
        response = _service.get_configuration(
            name,
            x_sm_accept_configuration_type=x_sm_accept_configuration_type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_configuration_all_params_with_retries(self):
        # Enable retries and run test_get_configuration_all_params.
        _service.enable_retries()
        self.test_get_configuration_all_params()

        # Disable retries and run test_get_configuration_all_params.
        _service.disable_retries()
        self.test_get_configuration_all_params()

    @responses.activate
    def test_get_configuration_required_params(self):
        """
        test_get_configuration_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        name = 'configuration-name'

        # Invoke method
        response = _service.get_configuration(
            name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_configuration_required_params_with_retries(self):
        # Enable retries and run test_get_configuration_required_params.
        _service.enable_retries()
        self.test_get_configuration_required_params()

        # Disable retries and run test_get_configuration_required_params.
        _service.disable_retries()
        self.test_get_configuration_required_params()

    @responses.activate
    def test_get_configuration_value_error(self):
        """
        test_get_configuration_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Set up parameter values
        name = 'configuration-name'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "name": name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_configuration(**req_copy)

    def test_get_configuration_value_error_with_retries(self):
        # Enable retries and run test_get_configuration_value_error.
        _service.enable_retries()
        self.test_get_configuration_value_error()

        # Disable retries and run test_get_configuration_value_error.
        _service.disable_retries()
        self.test_get_configuration_value_error()


class TestUpdateConfiguration:
    """
    Test Class for update_configuration
    """

    @responses.activate
    def test_update_configuration_all_params(self):
        """
        update_configuration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPatch model
        configuration_patch_model = {}
        configuration_patch_model['cloud_internet_services_apikey'] = '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ'
        configuration_patch_model[
            'cloud_internet_services_crn'] = 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::'

        # Set up parameter values
        name = 'configuration-name'
        configuration_patch = configuration_patch_model
        x_sm_accept_configuration_type = 'public_cert_configuration_dns_cloud_internet_services'

        # Invoke method
        response = _service.update_configuration(
            name,
            configuration_patch,
            x_sm_accept_configuration_type=x_sm_accept_configuration_type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == configuration_patch

    def test_update_configuration_all_params_with_retries(self):
        # Enable retries and run test_update_configuration_all_params.
        _service.enable_retries()
        self.test_update_configuration_all_params()

        # Disable retries and run test_update_configuration_all_params.
        _service.disable_retries()
        self.test_update_configuration_all_params()

    @responses.activate
    def test_update_configuration_required_params(self):
        """
        test_update_configuration_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPatch model
        configuration_patch_model = {}
        configuration_patch_model['cloud_internet_services_apikey'] = '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ'
        configuration_patch_model[
            'cloud_internet_services_crn'] = 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::'

        # Set up parameter values
        name = 'configuration-name'
        configuration_patch = configuration_patch_model

        # Invoke method
        response = _service.update_configuration(
            name,
            configuration_patch,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == configuration_patch

    def test_update_configuration_required_params_with_retries(self):
        # Enable retries and run test_update_configuration_required_params.
        _service.enable_retries()
        self.test_update_configuration_required_params()

        # Disable retries and run test_update_configuration_required_params.
        _service.disable_retries()
        self.test_update_configuration_required_params()

    @responses.activate
    def test_update_configuration_value_error(self):
        """
        test_update_configuration_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        mock_response = '{"config_type": "public_cert_configuration_ca_lets_encrypt", "name": "my-secret-engine-config", "secret_type": "arbitrary", "created_by": "iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21", "created_at": "2022-04-12T23:20:50.520Z", "updated_at": "2022-04-12T23:20:50.520Z", "lets_encrypt_environment": "production", "lets_encrypt_preferred_chain": "lets_encrypt_preferred_chain", "lets_encrypt_private_key": "lets_encrypt_private_key"}'
        responses.add(
            responses.PATCH,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPatch model
        configuration_patch_model = {}
        configuration_patch_model['cloud_internet_services_apikey'] = '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ'
        configuration_patch_model[
            'cloud_internet_services_crn'] = 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::'

        # Set up parameter values
        name = 'configuration-name'
        configuration_patch = configuration_patch_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "name": name,
            "configuration_patch": configuration_patch,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_configuration(**req_copy)

    def test_update_configuration_value_error_with_retries(self):
        # Enable retries and run test_update_configuration_value_error.
        _service.enable_retries()
        self.test_update_configuration_value_error()

        # Disable retries and run test_update_configuration_value_error.
        _service.disable_retries()
        self.test_update_configuration_value_error()


class TestDeleteConfiguration:
    """
    Test Class for delete_configuration
    """

    @responses.activate
    def test_delete_configuration_all_params(self):
        """
        delete_configuration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        name = 'configuration-name'
        x_sm_accept_configuration_type = 'public_cert_configuration_dns_cloud_internet_services'

        # Invoke method
        response = _service.delete_configuration(
            name,
            x_sm_accept_configuration_type=x_sm_accept_configuration_type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_configuration_all_params_with_retries(self):
        # Enable retries and run test_delete_configuration_all_params.
        _service.enable_retries()
        self.test_delete_configuration_all_params()

        # Disable retries and run test_delete_configuration_all_params.
        _service.disable_retries()
        self.test_delete_configuration_all_params()

    @responses.activate
    def test_delete_configuration_required_params(self):
        """
        test_delete_configuration_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        name = 'configuration-name'

        # Invoke method
        response = _service.delete_configuration(
            name,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_configuration_required_params_with_retries(self):
        # Enable retries and run test_delete_configuration_required_params.
        _service.enable_retries()
        self.test_delete_configuration_required_params()

        # Disable retries and run test_delete_configuration_required_params.
        _service.disable_retries()
        self.test_delete_configuration_required_params()

    @responses.activate
    def test_delete_configuration_value_error(self):
        """
        test_delete_configuration_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Set up parameter values
        name = 'configuration-name'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "name": name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_configuration(**req_copy)

    def test_delete_configuration_value_error_with_retries(self):
        # Enable retries and run test_delete_configuration_value_error.
        _service.enable_retries()
        self.test_delete_configuration_value_error()

        # Disable retries and run test_delete_configuration_value_error.
        _service.disable_retries()
        self.test_delete_configuration_value_error()


class TestCreateConfigurationAction:
    """
    Test Class for create_configuration_action
    """

    @responses.activate
    def test_create_configuration_action_all_params(self):
        """
        create_configuration_action()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name/actions')
        mock_response = '{"action_type": "private_cert_configuration_action_revoke_ca_certificate", "revocation_time_seconds": 1577836800}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateConfigurationActionRotateCRLPrototype model
        configuration_action_prototype_model = {}
        configuration_action_prototype_model['action_type'] = 'private_cert_configuration_action_rotate_crl'

        # Set up parameter values
        name = 'configuration-name'
        config_action_prototype = configuration_action_prototype_model
        x_sm_accept_configuration_type = 'public_cert_configuration_dns_cloud_internet_services'

        # Invoke method
        response = _service.create_configuration_action(
            name,
            config_action_prototype,
            x_sm_accept_configuration_type=x_sm_accept_configuration_type,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == config_action_prototype

    def test_create_configuration_action_all_params_with_retries(self):
        # Enable retries and run test_create_configuration_action_all_params.
        _service.enable_retries()
        self.test_create_configuration_action_all_params()

        # Disable retries and run test_create_configuration_action_all_params.
        _service.disable_retries()
        self.test_create_configuration_action_all_params()

    @responses.activate
    def test_create_configuration_action_required_params(self):
        """
        test_create_configuration_action_required_params()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name/actions')
        mock_response = '{"action_type": "private_cert_configuration_action_revoke_ca_certificate", "revocation_time_seconds": 1577836800}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateConfigurationActionRotateCRLPrototype model
        configuration_action_prototype_model = {}
        configuration_action_prototype_model['action_type'] = 'private_cert_configuration_action_rotate_crl'

        # Set up parameter values
        name = 'configuration-name'
        config_action_prototype = configuration_action_prototype_model

        # Invoke method
        response = _service.create_configuration_action(
            name,
            config_action_prototype,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == config_action_prototype

    def test_create_configuration_action_required_params_with_retries(self):
        # Enable retries and run test_create_configuration_action_required_params.
        _service.enable_retries()
        self.test_create_configuration_action_required_params()

        # Disable retries and run test_create_configuration_action_required_params.
        _service.disable_retries()
        self.test_create_configuration_action_required_params()

    @responses.activate
    def test_create_configuration_action_value_error(self):
        """
        test_create_configuration_action_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/configurations/configuration-name/actions')
        mock_response = '{"action_type": "private_cert_configuration_action_revoke_ca_certificate", "revocation_time_seconds": 1577836800}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Construct a dict representation of a PrivateCertificateConfigurationActionRotateCRLPrototype model
        configuration_action_prototype_model = {}
        configuration_action_prototype_model['action_type'] = 'private_cert_configuration_action_rotate_crl'

        # Set up parameter values
        name = 'configuration-name'
        config_action_prototype = configuration_action_prototype_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "name": name,
            "config_action_prototype": config_action_prototype,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_configuration_action(**req_copy)

    def test_create_configuration_action_value_error_with_retries(self):
        # Enable retries and run test_create_configuration_action_value_error.
        _service.enable_retries()
        self.test_create_configuration_action_value_error()

        # Disable retries and run test_create_configuration_action_value_error.
        _service.disable_retries()
        self.test_create_configuration_action_value_error()


# endregion
##############################################################################
# End of Service: Configurations
##############################################################################

##############################################################################
# Start of Service: Notifications
##############################################################################
# region


class TestNewInstance:
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV2.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV2)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV2.new_instance(
                service_name='TEST_SERVICE_NOT_FOUND',
            )


class TestCreateNotificationsRegistration:
    """
    Test Class for create_notifications_registration
    """

    @responses.activate
    def test_create_notifications_registration_all_params(self):
        """
        create_notifications_registration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/notifications/registration')
        mock_response = '{"event_notifications_instance_crn": "event_notifications_instance_crn"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        event_notifications_instance_crn = 'crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::'
        event_notifications_source_name = 'My Secrets Manager'
        event_notifications_source_description = 'Optional description of this source in an Event Notifications instance.'

        # Invoke method
        response = _service.create_notifications_registration(
            event_notifications_instance_crn,
            event_notifications_source_name,
            event_notifications_source_description=event_notifications_source_description,
            headers={},
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body[
                   'event_notifications_instance_crn'] == 'crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::'
        assert req_body['event_notifications_source_name'] == 'My Secrets Manager'
        assert req_body[
                   'event_notifications_source_description'] == 'Optional description of this source in an Event Notifications instance.'

    def test_create_notifications_registration_all_params_with_retries(self):
        # Enable retries and run test_create_notifications_registration_all_params.
        _service.enable_retries()
        self.test_create_notifications_registration_all_params()

        # Disable retries and run test_create_notifications_registration_all_params.
        _service.disable_retries()
        self.test_create_notifications_registration_all_params()

    @responses.activate
    def test_create_notifications_registration_value_error(self):
        """
        test_create_notifications_registration_value_error()
        """
        # Set up mock
        url = preprocess_url('/api/v2/notifications/registration')
        mock_response = '{"event_notifications_instance_crn": "event_notifications_instance_crn"}'
        responses.add(
            responses.POST,
            url,
            body=mock_response,
            content_type='application/json',
            status=201,
        )

        # Set up parameter values
        event_notifications_instance_crn = 'crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::'
        event_notifications_source_name = 'My Secrets Manager'
        event_notifications_source_description = 'Optional description of this source in an Event Notifications instance.'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "event_notifications_instance_crn": event_notifications_instance_crn,
            "event_notifications_source_name": event_notifications_source_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_notifications_registration(**req_copy)

    def test_create_notifications_registration_value_error_with_retries(self):
        # Enable retries and run test_create_notifications_registration_value_error.
        _service.enable_retries()
        self.test_create_notifications_registration_value_error()

        # Disable retries and run test_create_notifications_registration_value_error.
        _service.disable_retries()
        self.test_create_notifications_registration_value_error()


class TestGetNotificationsRegistration:
    """
    Test Class for get_notifications_registration
    """

    @responses.activate
    def test_get_notifications_registration_all_params(self):
        """
        get_notifications_registration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/notifications/registration')
        mock_response = '{"event_notifications_instance_crn": "event_notifications_instance_crn"}'
        responses.add(
            responses.GET,
            url,
            body=mock_response,
            content_type='application/json',
            status=200,
        )

        # Invoke method
        response = _service.get_notifications_registration()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    def test_get_notifications_registration_all_params_with_retries(self):
        # Enable retries and run test_get_notifications_registration_all_params.
        _service.enable_retries()
        self.test_get_notifications_registration_all_params()

        # Disable retries and run test_get_notifications_registration_all_params.
        _service.disable_retries()
        self.test_get_notifications_registration_all_params()


class TestDeleteNotificationsRegistration:
    """
    Test Class for delete_notifications_registration
    """

    @responses.activate
    def test_delete_notifications_registration_all_params(self):
        """
        delete_notifications_registration()
        """
        # Set up mock
        url = preprocess_url('/api/v2/notifications/registration')
        responses.add(
            responses.DELETE,
            url,
            status=204,
        )

        # Invoke method
        response = _service.delete_notifications_registration()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_delete_notifications_registration_all_params_with_retries(self):
        # Enable retries and run test_delete_notifications_registration_all_params.
        _service.enable_retries()
        self.test_delete_notifications_registration_all_params()

        # Disable retries and run test_delete_notifications_registration_all_params.
        _service.disable_retries()
        self.test_delete_notifications_registration_all_params()


class TestGetNotificationsRegistrationTest:
    """
    Test Class for get_notifications_registration_test
    """

    @responses.activate
    def test_get_notifications_registration_test_all_params(self):
        """
        get_notifications_registration_test()
        """
        # Set up mock
        url = preprocess_url('/api/v2/notifications/registration/test')
        responses.add(
            responses.GET,
            url,
            status=204,
        )

        # Invoke method
        response = _service.get_notifications_registration_test()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    def test_get_notifications_registration_test_all_params_with_retries(self):
        # Enable retries and run test_get_notifications_registration_test_all_params.
        _service.enable_retries()
        self.test_get_notifications_registration_test_all_params()

        # Disable retries and run test_get_notifications_registration_test_all_params.
        _service.disable_retries()
        self.test_get_notifications_registration_test_all_params()


# endregion
##############################################################################
# End of Service: Notifications
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region


class TestModel_CertificateIssuanceInfo:
    """
    Test Class for CertificateIssuanceInfo
    """

    def test_certificate_issuance_info_serialization(self):
        """
        Test serialization/deserialization for CertificateIssuanceInfo
        """

        # Construct a json representation of a CertificateIssuanceInfo model
        certificate_issuance_info_model_json = {}

        # Construct a model instance of CertificateIssuanceInfo by calling from_dict on the json representation
        certificate_issuance_info_model = CertificateIssuanceInfo.from_dict(certificate_issuance_info_model_json)
        assert certificate_issuance_info_model != False

        # Construct a model instance of CertificateIssuanceInfo by calling from_dict on the json representation
        certificate_issuance_info_model_dict = CertificateIssuanceInfo.from_dict(
            certificate_issuance_info_model_json).__dict__
        certificate_issuance_info_model2 = CertificateIssuanceInfo(**certificate_issuance_info_model_dict)

        # Verify the model instances are equivalent
        assert certificate_issuance_info_model == certificate_issuance_info_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_issuance_info_model_json2 = certificate_issuance_info_model.to_dict()
        assert certificate_issuance_info_model_json2 == certificate_issuance_info_model_json


class TestModel_CertificateValidity:
    """
    Test Class for CertificateValidity
    """

    def test_certificate_validity_serialization(self):
        """
        Test serialization/deserialization for CertificateValidity
        """

        # Construct a json representation of a CertificateValidity model
        certificate_validity_model_json = {}
        certificate_validity_model_json['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model_json['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a model instance of CertificateValidity by calling from_dict on the json representation
        certificate_validity_model = CertificateValidity.from_dict(certificate_validity_model_json)
        assert certificate_validity_model != False

        # Construct a model instance of CertificateValidity by calling from_dict on the json representation
        certificate_validity_model_dict = CertificateValidity.from_dict(certificate_validity_model_json).__dict__
        certificate_validity_model2 = CertificateValidity(**certificate_validity_model_dict)

        # Verify the model instances are equivalent
        assert certificate_validity_model == certificate_validity_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_validity_model_json2 = certificate_validity_model.to_dict()
        assert certificate_validity_model_json2 == certificate_validity_model_json


class TestModel_ChallengeResource:
    """
    Test Class for ChallengeResource
    """

    def test_challenge_resource_serialization(self):
        """
        Test serialization/deserialization for ChallengeResource
        """

        # Construct a json representation of a ChallengeResource model
        challenge_resource_model_json = {}

        # Construct a model instance of ChallengeResource by calling from_dict on the json representation
        challenge_resource_model = ChallengeResource.from_dict(challenge_resource_model_json)
        assert challenge_resource_model != False

        # Construct a model instance of ChallengeResource by calling from_dict on the json representation
        challenge_resource_model_dict = ChallengeResource.from_dict(challenge_resource_model_json).__dict__
        challenge_resource_model2 = ChallengeResource(**challenge_resource_model_dict)

        # Verify the model instances are equivalent
        assert challenge_resource_model == challenge_resource_model2

        # Convert model instance back to dict and verify no loss of data
        challenge_resource_model_json2 = challenge_resource_model.to_dict()
        assert challenge_resource_model_json2 == challenge_resource_model_json


class TestModel_ConfigurationMetadataPaginatedCollection:
    """
    Test Class for ConfigurationMetadataPaginatedCollection
    """

    def test_configuration_metadata_paginated_collection_serialization(self):
        """
        Test serialization/deserialization for ConfigurationMetadataPaginatedCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        paginated_collection_first_model = {}  # PaginatedCollectionFirst
        paginated_collection_first_model['href'] = 'testString'

        paginated_collection_next_model = {}  # PaginatedCollectionNext
        paginated_collection_next_model['href'] = 'testString'

        paginated_collection_previous_model = {}  # PaginatedCollectionPrevious
        paginated_collection_previous_model['href'] = 'testString'

        paginated_collection_last_model = {}  # PaginatedCollectionLast
        paginated_collection_last_model['href'] = 'testString'

        configuration_metadata_model = {}  # IAMCredentialsConfigurationMetadata
        configuration_metadata_model['config_type'] = 'iam_credentials_configuration'
        configuration_metadata_model['name'] = 'my-secret-engine-config'
        configuration_metadata_model['secret_type'] = 'arbitrary'
        configuration_metadata_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        configuration_metadata_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        configuration_metadata_model['updated_at'] = '2022-04-12T23:20:50.520000Z'
        configuration_metadata_model['disabled'] = True

        # Construct a json representation of a ConfigurationMetadataPaginatedCollection model
        configuration_metadata_paginated_collection_model_json = {}
        configuration_metadata_paginated_collection_model_json['total_count'] = 0
        configuration_metadata_paginated_collection_model_json['limit'] = 25
        configuration_metadata_paginated_collection_model_json['offset'] = 25
        configuration_metadata_paginated_collection_model_json['first'] = paginated_collection_first_model
        configuration_metadata_paginated_collection_model_json['next'] = paginated_collection_next_model
        configuration_metadata_paginated_collection_model_json['previous'] = paginated_collection_previous_model
        configuration_metadata_paginated_collection_model_json['last'] = paginated_collection_last_model
        configuration_metadata_paginated_collection_model_json['configurations'] = [configuration_metadata_model]

        # Construct a model instance of ConfigurationMetadataPaginatedCollection by calling from_dict on the json representation
        configuration_metadata_paginated_collection_model = ConfigurationMetadataPaginatedCollection.from_dict(
            configuration_metadata_paginated_collection_model_json)
        assert configuration_metadata_paginated_collection_model != False

        # Construct a model instance of ConfigurationMetadataPaginatedCollection by calling from_dict on the json representation
        configuration_metadata_paginated_collection_model_dict = ConfigurationMetadataPaginatedCollection.from_dict(
            configuration_metadata_paginated_collection_model_json).__dict__
        configuration_metadata_paginated_collection_model2 = ConfigurationMetadataPaginatedCollection(
            **configuration_metadata_paginated_collection_model_dict)

        # Verify the model instances are equivalent
        assert configuration_metadata_paginated_collection_model == configuration_metadata_paginated_collection_model2

        # Convert model instance back to dict and verify no loss of data
        configuration_metadata_paginated_collection_model_json2 = configuration_metadata_paginated_collection_model.to_dict()
        assert configuration_metadata_paginated_collection_model_json2 == configuration_metadata_paginated_collection_model_json


class TestModel_ImportedCertificateManagedCsr:
    """
    Test Class for ImportedCertificateManagedCsr
    """

    def test_imported_certificate_managed_csr_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateManagedCsr
        """

        # Construct a json representation of a ImportedCertificateManagedCsr model
        imported_certificate_managed_csr_model_json = {}
        imported_certificate_managed_csr_model_json['ou'] = ['testString']
        imported_certificate_managed_csr_model_json['organization'] = ['testString']
        imported_certificate_managed_csr_model_json['country'] = ['testString']
        imported_certificate_managed_csr_model_json['locality'] = ['testString']
        imported_certificate_managed_csr_model_json['province'] = ['testString']
        imported_certificate_managed_csr_model_json['street_address'] = ['testString']
        imported_certificate_managed_csr_model_json['postal_code'] = ['testString']
        imported_certificate_managed_csr_model_json['require_cn'] = True
        imported_certificate_managed_csr_model_json['common_name'] = 'example.com'
        imported_certificate_managed_csr_model_json['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_model_json['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_model_json['uri_sans'] = 'testString'
        imported_certificate_managed_csr_model_json['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_model_json['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_model_json['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_model_json['server_flag'] = True
        imported_certificate_managed_csr_model_json['client_flag'] = True
        imported_certificate_managed_csr_model_json['code_signing_flag'] = True
        imported_certificate_managed_csr_model_json['email_protection_flag'] = True
        imported_certificate_managed_csr_model_json['key_type'] = 'rsa'
        imported_certificate_managed_csr_model_json['key_bits'] = 4096
        imported_certificate_managed_csr_model_json['key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_model_json['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_model_json['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_model_json['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_model_json['rotate_keys'] = True

        # Construct a model instance of ImportedCertificateManagedCsr by calling from_dict on the json representation
        imported_certificate_managed_csr_model = ImportedCertificateManagedCsr.from_dict(
            imported_certificate_managed_csr_model_json)
        assert imported_certificate_managed_csr_model != False

        # Construct a model instance of ImportedCertificateManagedCsr by calling from_dict on the json representation
        imported_certificate_managed_csr_model_dict = ImportedCertificateManagedCsr.from_dict(
            imported_certificate_managed_csr_model_json).__dict__
        imported_certificate_managed_csr_model2 = ImportedCertificateManagedCsr(
            **imported_certificate_managed_csr_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_managed_csr_model == imported_certificate_managed_csr_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_managed_csr_model_json2 = imported_certificate_managed_csr_model.to_dict()
        assert imported_certificate_managed_csr_model_json2 == imported_certificate_managed_csr_model_json


class TestModel_ImportedCertificateManagedCsrResponse:
    """
    Test Class for ImportedCertificateManagedCsrResponse
    """

    def test_imported_certificate_managed_csr_response_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateManagedCsrResponse
        """

        # Construct a json representation of a ImportedCertificateManagedCsrResponse model
        imported_certificate_managed_csr_response_model_json = {}
        imported_certificate_managed_csr_response_model_json['ou'] = ['testString']
        imported_certificate_managed_csr_response_model_json['organization'] = ['testString']
        imported_certificate_managed_csr_response_model_json['country'] = ['testString']
        imported_certificate_managed_csr_response_model_json['locality'] = ['testString']
        imported_certificate_managed_csr_response_model_json['province'] = ['testString']
        imported_certificate_managed_csr_response_model_json['street_address'] = ['testString']
        imported_certificate_managed_csr_response_model_json['postal_code'] = ['testString']
        imported_certificate_managed_csr_response_model_json['require_cn'] = True
        imported_certificate_managed_csr_response_model_json['common_name'] = 'example.com'
        imported_certificate_managed_csr_response_model_json['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_response_model_json['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_response_model_json['uri_sans'] = 'testString'
        imported_certificate_managed_csr_response_model_json['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_response_model_json['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_response_model_json['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_response_model_json['server_flag'] = True
        imported_certificate_managed_csr_response_model_json['client_flag'] = True
        imported_certificate_managed_csr_response_model_json['code_signing_flag'] = True
        imported_certificate_managed_csr_response_model_json['email_protection_flag'] = True
        imported_certificate_managed_csr_response_model_json['key_type'] = 'rsa'
        imported_certificate_managed_csr_response_model_json['key_bits'] = 4096
        imported_certificate_managed_csr_response_model_json[
            'key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_response_model_json['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_response_model_json['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_response_model_json['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_response_model_json['rotate_keys'] = True
        imported_certificate_managed_csr_response_model_json['csr'] = 'testString'
        imported_certificate_managed_csr_response_model_json['private_key'] = 'testString'

        # Construct a model instance of ImportedCertificateManagedCsrResponse by calling from_dict on the json representation
        imported_certificate_managed_csr_response_model = ImportedCertificateManagedCsrResponse.from_dict(
            imported_certificate_managed_csr_response_model_json)
        assert imported_certificate_managed_csr_response_model != False

        # Construct a model instance of ImportedCertificateManagedCsrResponse by calling from_dict on the json representation
        imported_certificate_managed_csr_response_model_dict = ImportedCertificateManagedCsrResponse.from_dict(
            imported_certificate_managed_csr_response_model_json).__dict__
        imported_certificate_managed_csr_response_model2 = ImportedCertificateManagedCsrResponse(
            **imported_certificate_managed_csr_response_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_managed_csr_response_model == imported_certificate_managed_csr_response_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_managed_csr_response_model_json2 = imported_certificate_managed_csr_response_model.to_dict()
        assert imported_certificate_managed_csr_response_model_json2 == imported_certificate_managed_csr_response_model_json


class TestModel_NotificationsRegistration:
    """
    Test Class for NotificationsRegistration
    """

    def test_notifications_registration_serialization(self):
        """
        Test serialization/deserialization for NotificationsRegistration
        """

        # Construct a json representation of a NotificationsRegistration model
        notifications_registration_model_json = {}
        notifications_registration_model_json['event_notifications_instance_crn'] = 'testString'

        # Construct a model instance of NotificationsRegistration by calling from_dict on the json representation
        notifications_registration_model = NotificationsRegistration.from_dict(notifications_registration_model_json)
        assert notifications_registration_model != False

        # Construct a model instance of NotificationsRegistration by calling from_dict on the json representation
        notifications_registration_model_dict = NotificationsRegistration.from_dict(
            notifications_registration_model_json).__dict__
        notifications_registration_model2 = NotificationsRegistration(**notifications_registration_model_dict)

        # Verify the model instances are equivalent
        assert notifications_registration_model == notifications_registration_model2

        # Convert model instance back to dict and verify no loss of data
        notifications_registration_model_json2 = notifications_registration_model.to_dict()
        assert notifications_registration_model_json2 == notifications_registration_model_json


class TestModel_PaginatedCollectionFirst:
    """
    Test Class for PaginatedCollectionFirst
    """

    def test_paginated_collection_first_serialization(self):
        """
        Test serialization/deserialization for PaginatedCollectionFirst
        """

        # Construct a json representation of a PaginatedCollectionFirst model
        paginated_collection_first_model_json = {}
        paginated_collection_first_model_json['href'] = 'testString'

        # Construct a model instance of PaginatedCollectionFirst by calling from_dict on the json representation
        paginated_collection_first_model = PaginatedCollectionFirst.from_dict(paginated_collection_first_model_json)
        assert paginated_collection_first_model != False

        # Construct a model instance of PaginatedCollectionFirst by calling from_dict on the json representation
        paginated_collection_first_model_dict = PaginatedCollectionFirst.from_dict(
            paginated_collection_first_model_json).__dict__
        paginated_collection_first_model2 = PaginatedCollectionFirst(**paginated_collection_first_model_dict)

        # Verify the model instances are equivalent
        assert paginated_collection_first_model == paginated_collection_first_model2

        # Convert model instance back to dict and verify no loss of data
        paginated_collection_first_model_json2 = paginated_collection_first_model.to_dict()
        assert paginated_collection_first_model_json2 == paginated_collection_first_model_json


class TestModel_PaginatedCollectionLast:
    """
    Test Class for PaginatedCollectionLast
    """

    def test_paginated_collection_last_serialization(self):
        """
        Test serialization/deserialization for PaginatedCollectionLast
        """

        # Construct a json representation of a PaginatedCollectionLast model
        paginated_collection_last_model_json = {}
        paginated_collection_last_model_json['href'] = 'testString'

        # Construct a model instance of PaginatedCollectionLast by calling from_dict on the json representation
        paginated_collection_last_model = PaginatedCollectionLast.from_dict(paginated_collection_last_model_json)
        assert paginated_collection_last_model != False

        # Construct a model instance of PaginatedCollectionLast by calling from_dict on the json representation
        paginated_collection_last_model_dict = PaginatedCollectionLast.from_dict(
            paginated_collection_last_model_json).__dict__
        paginated_collection_last_model2 = PaginatedCollectionLast(**paginated_collection_last_model_dict)

        # Verify the model instances are equivalent
        assert paginated_collection_last_model == paginated_collection_last_model2

        # Convert model instance back to dict and verify no loss of data
        paginated_collection_last_model_json2 = paginated_collection_last_model.to_dict()
        assert paginated_collection_last_model_json2 == paginated_collection_last_model_json


class TestModel_PaginatedCollectionNext:
    """
    Test Class for PaginatedCollectionNext
    """

    def test_paginated_collection_next_serialization(self):
        """
        Test serialization/deserialization for PaginatedCollectionNext
        """

        # Construct a json representation of a PaginatedCollectionNext model
        paginated_collection_next_model_json = {}
        paginated_collection_next_model_json['href'] = 'testString'

        # Construct a model instance of PaginatedCollectionNext by calling from_dict on the json representation
        paginated_collection_next_model = PaginatedCollectionNext.from_dict(paginated_collection_next_model_json)
        assert paginated_collection_next_model != False

        # Construct a model instance of PaginatedCollectionNext by calling from_dict on the json representation
        paginated_collection_next_model_dict = PaginatedCollectionNext.from_dict(
            paginated_collection_next_model_json).__dict__
        paginated_collection_next_model2 = PaginatedCollectionNext(**paginated_collection_next_model_dict)

        # Verify the model instances are equivalent
        assert paginated_collection_next_model == paginated_collection_next_model2

        # Convert model instance back to dict and verify no loss of data
        paginated_collection_next_model_json2 = paginated_collection_next_model.to_dict()
        assert paginated_collection_next_model_json2 == paginated_collection_next_model_json


class TestModel_PaginatedCollectionPrevious:
    """
    Test Class for PaginatedCollectionPrevious
    """

    def test_paginated_collection_previous_serialization(self):
        """
        Test serialization/deserialization for PaginatedCollectionPrevious
        """

        # Construct a json representation of a PaginatedCollectionPrevious model
        paginated_collection_previous_model_json = {}
        paginated_collection_previous_model_json['href'] = 'testString'

        # Construct a model instance of PaginatedCollectionPrevious by calling from_dict on the json representation
        paginated_collection_previous_model = PaginatedCollectionPrevious.from_dict(
            paginated_collection_previous_model_json)
        assert paginated_collection_previous_model != False

        # Construct a model instance of PaginatedCollectionPrevious by calling from_dict on the json representation
        paginated_collection_previous_model_dict = PaginatedCollectionPrevious.from_dict(
            paginated_collection_previous_model_json).__dict__
        paginated_collection_previous_model2 = PaginatedCollectionPrevious(**paginated_collection_previous_model_dict)

        # Verify the model instances are equivalent
        assert paginated_collection_previous_model == paginated_collection_previous_model2

        # Convert model instance back to dict and verify no loss of data
        paginated_collection_previous_model_json2 = paginated_collection_previous_model.to_dict()
        assert paginated_collection_previous_model_json2 == paginated_collection_previous_model_json


class TestModel_PasswordGenerationPolicy:
    """
    Test Class for PasswordGenerationPolicy
    """

    def test_password_generation_policy_serialization(self):
        """
        Test serialization/deserialization for PasswordGenerationPolicy
        """

        # Construct a json representation of a PasswordGenerationPolicy model
        password_generation_policy_model_json = {}
        password_generation_policy_model_json['length'] = 32
        password_generation_policy_model_json['include_digits'] = True
        password_generation_policy_model_json['include_symbols'] = True
        password_generation_policy_model_json['include_uppercase'] = True

        # Construct a model instance of PasswordGenerationPolicy by calling from_dict on the json representation
        password_generation_policy_model = PasswordGenerationPolicy.from_dict(password_generation_policy_model_json)
        assert password_generation_policy_model != False

        # Construct a model instance of PasswordGenerationPolicy by calling from_dict on the json representation
        password_generation_policy_model_dict = PasswordGenerationPolicy.from_dict(
            password_generation_policy_model_json).__dict__
        password_generation_policy_model2 = PasswordGenerationPolicy(**password_generation_policy_model_dict)

        # Verify the model instances are equivalent
        assert password_generation_policy_model == password_generation_policy_model2

        # Convert model instance back to dict and verify no loss of data
        password_generation_policy_model_json2 = password_generation_policy_model.to_dict()
        assert password_generation_policy_model_json2 == password_generation_policy_model_json


class TestModel_PasswordGenerationPolicyPatch:
    """
    Test Class for PasswordGenerationPolicyPatch
    """

    def test_password_generation_policy_patch_serialization(self):
        """
        Test serialization/deserialization for PasswordGenerationPolicyPatch
        """

        # Construct a json representation of a PasswordGenerationPolicyPatch model
        password_generation_policy_patch_model_json = {}
        password_generation_policy_patch_model_json['length'] = 12
        password_generation_policy_patch_model_json['include_digits'] = True
        password_generation_policy_patch_model_json['include_symbols'] = True
        password_generation_policy_patch_model_json['include_uppercase'] = True

        # Construct a model instance of PasswordGenerationPolicyPatch by calling from_dict on the json representation
        password_generation_policy_patch_model = PasswordGenerationPolicyPatch.from_dict(
            password_generation_policy_patch_model_json)
        assert password_generation_policy_patch_model != False

        # Construct a model instance of PasswordGenerationPolicyPatch by calling from_dict on the json representation
        password_generation_policy_patch_model_dict = PasswordGenerationPolicyPatch.from_dict(
            password_generation_policy_patch_model_json).__dict__
        password_generation_policy_patch_model2 = PasswordGenerationPolicyPatch(
            **password_generation_policy_patch_model_dict)

        # Verify the model instances are equivalent
        assert password_generation_policy_patch_model == password_generation_policy_patch_model2

        # Convert model instance back to dict and verify no loss of data
        password_generation_policy_patch_model_json2 = password_generation_policy_patch_model.to_dict()
        assert password_generation_policy_patch_model_json2 == password_generation_policy_patch_model_json


class TestModel_PasswordGenerationPolicyRO:
    """
    Test Class for PasswordGenerationPolicyRO
    """

    def test_password_generation_policy_ro_serialization(self):
        """
        Test serialization/deserialization for PasswordGenerationPolicyRO
        """

        # Construct a json representation of a PasswordGenerationPolicyRO model
        password_generation_policy_ro_model_json = {}
        password_generation_policy_ro_model_json['length'] = 12
        password_generation_policy_ro_model_json['include_digits'] = True
        password_generation_policy_ro_model_json['include_symbols'] = True
        password_generation_policy_ro_model_json['include_uppercase'] = True

        # Construct a model instance of PasswordGenerationPolicyRO by calling from_dict on the json representation
        password_generation_policy_ro_model = PasswordGenerationPolicyRO.from_dict(
            password_generation_policy_ro_model_json)
        assert password_generation_policy_ro_model != False

        # Construct a model instance of PasswordGenerationPolicyRO by calling from_dict on the json representation
        password_generation_policy_ro_model_dict = PasswordGenerationPolicyRO.from_dict(
            password_generation_policy_ro_model_json).__dict__
        password_generation_policy_ro_model2 = PasswordGenerationPolicyRO(**password_generation_policy_ro_model_dict)

        # Verify the model instances are equivalent
        assert password_generation_policy_ro_model == password_generation_policy_ro_model2

        # Convert model instance back to dict and verify no loss of data
        password_generation_policy_ro_model_json2 = password_generation_policy_ro_model.to_dict()
        assert password_generation_policy_ro_model_json2 == password_generation_policy_ro_model_json


class TestModel_PrivateCertificateConfigurationRotateAction:
    """
    Test Class for PrivateCertificateConfigurationRotateAction
    """

    def test_private_certificate_configuration_rotate_action_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationRotateAction
        """

        # Construct a json representation of a PrivateCertificateConfigurationRotateAction model
        private_certificate_configuration_rotate_action_model_json = {}
        private_certificate_configuration_rotate_action_model_json['common_name'] = 'localhost'
        private_certificate_configuration_rotate_action_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_configuration_rotate_action_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_rotate_action_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_rotate_action_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_rotate_action_model_json['format'] = 'pem'
        private_certificate_configuration_rotate_action_model_json['max_path_length'] = -1
        private_certificate_configuration_rotate_action_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_rotate_action_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['use_csr_values'] = True
        private_certificate_configuration_rotate_action_model_json['ou'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['organization'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['country'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['locality'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['province'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['street_address'] = ['testString']
        private_certificate_configuration_rotate_action_model_json['postal_code'] = ['testString']
        private_certificate_configuration_rotate_action_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_rotate_action_model_json['csr'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationRotateAction by calling from_dict on the json representation
        private_certificate_configuration_rotate_action_model = PrivateCertificateConfigurationRotateAction.from_dict(
            private_certificate_configuration_rotate_action_model_json)
        assert private_certificate_configuration_rotate_action_model != False

        # Construct a model instance of PrivateCertificateConfigurationRotateAction by calling from_dict on the json representation
        private_certificate_configuration_rotate_action_model_dict = PrivateCertificateConfigurationRotateAction.from_dict(
            private_certificate_configuration_rotate_action_model_json).__dict__
        private_certificate_configuration_rotate_action_model2 = PrivateCertificateConfigurationRotateAction(
            **private_certificate_configuration_rotate_action_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_rotate_action_model == private_certificate_configuration_rotate_action_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_rotate_action_model_json2 = private_certificate_configuration_rotate_action_model.to_dict()
        assert private_certificate_configuration_rotate_action_model_json2 == private_certificate_configuration_rotate_action_model_json


class TestModel_PrivateCertificateCryptoKey:
    """
    Test Class for PrivateCertificateCryptoKey
    """

    def test_private_certificate_crypto_key_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateCryptoKey
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        # Construct a json representation of a PrivateCertificateCryptoKey model
        private_certificate_crypto_key_model_json = {}
        private_certificate_crypto_key_model_json['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model_json['label'] = 'my_key'
        private_certificate_crypto_key_model_json['allow_generate_key'] = False
        private_certificate_crypto_key_model_json['provider'] = private_certificate_crypto_provider_model

        # Construct a model instance of PrivateCertificateCryptoKey by calling from_dict on the json representation
        private_certificate_crypto_key_model = PrivateCertificateCryptoKey.from_dict(
            private_certificate_crypto_key_model_json)
        assert private_certificate_crypto_key_model != False

        # Construct a model instance of PrivateCertificateCryptoKey by calling from_dict on the json representation
        private_certificate_crypto_key_model_dict = PrivateCertificateCryptoKey.from_dict(
            private_certificate_crypto_key_model_json).__dict__
        private_certificate_crypto_key_model2 = PrivateCertificateCryptoKey(**private_certificate_crypto_key_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_crypto_key_model == private_certificate_crypto_key_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_crypto_key_model_json2 = private_certificate_crypto_key_model.to_dict()
        assert private_certificate_crypto_key_model_json2 == private_certificate_crypto_key_model_json


class TestModel_PublicCertificateRotationObject:
    """
    Test Class for PublicCertificateRotationObject
    """

    def test_public_certificate_rotation_object_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateRotationObject
        """

        # Construct a json representation of a PublicCertificateRotationObject model
        public_certificate_rotation_object_model_json = {}
        public_certificate_rotation_object_model_json['rotate_keys'] = True

        # Construct a model instance of PublicCertificateRotationObject by calling from_dict on the json representation
        public_certificate_rotation_object_model = PublicCertificateRotationObject.from_dict(
            public_certificate_rotation_object_model_json)
        assert public_certificate_rotation_object_model != False

        # Construct a model instance of PublicCertificateRotationObject by calling from_dict on the json representation
        public_certificate_rotation_object_model_dict = PublicCertificateRotationObject.from_dict(
            public_certificate_rotation_object_model_json).__dict__
        public_certificate_rotation_object_model2 = PublicCertificateRotationObject(
            **public_certificate_rotation_object_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_rotation_object_model == public_certificate_rotation_object_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_rotation_object_model_json2 = public_certificate_rotation_object_model.to_dict()
        assert public_certificate_rotation_object_model_json2 == public_certificate_rotation_object_model_json


class TestModel_SecretGroup:
    """
    Test Class for SecretGroup
    """

    def test_secret_group_serialization(self):
        """
        Test serialization/deserialization for SecretGroup
        """

        # Construct a json representation of a SecretGroup model
        secret_group_model_json = {}
        secret_group_model_json['id'] = 'default'
        secret_group_model_json['description'] = 'Extended description for this group.'
        secret_group_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_group_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_group_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'

        # Construct a model instance of SecretGroup by calling from_dict on the json representation
        secret_group_model = SecretGroup.from_dict(secret_group_model_json)
        assert secret_group_model != False

        # Construct a model instance of SecretGroup by calling from_dict on the json representation
        secret_group_model_dict = SecretGroup.from_dict(secret_group_model_json).__dict__
        secret_group_model2 = SecretGroup(**secret_group_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_model == secret_group_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_model_json2 = secret_group_model.to_dict()
        assert secret_group_model_json2 == secret_group_model_json


class TestModel_SecretGroupCollection:
    """
    Test Class for SecretGroupCollection
    """

    def test_secret_group_collection_serialization(self):
        """
        Test serialization/deserialization for SecretGroupCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_group_model = {}  # SecretGroup
        secret_group_model['id'] = 'default'
        secret_group_model['description'] = 'Extended description for this group.'
        secret_group_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_group_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_group_model['updated_at'] = '2022-04-12T23:20:50.520000Z'

        # Construct a json representation of a SecretGroupCollection model
        secret_group_collection_model_json = {}
        secret_group_collection_model_json['secret_groups'] = [secret_group_model]
        secret_group_collection_model_json['total_count'] = 0

        # Construct a model instance of SecretGroupCollection by calling from_dict on the json representation
        secret_group_collection_model = SecretGroupCollection.from_dict(secret_group_collection_model_json)
        assert secret_group_collection_model != False

        # Construct a model instance of SecretGroupCollection by calling from_dict on the json representation
        secret_group_collection_model_dict = SecretGroupCollection.from_dict(
            secret_group_collection_model_json).__dict__
        secret_group_collection_model2 = SecretGroupCollection(**secret_group_collection_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_collection_model == secret_group_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_collection_model_json2 = secret_group_collection_model.to_dict()
        assert secret_group_collection_model_json2 == secret_group_collection_model_json


class TestModel_SecretGroupPatch:
    """
    Test Class for SecretGroupPatch
    """

    def test_secret_group_patch_serialization(self):
        """
        Test serialization/deserialization for SecretGroupPatch
        """

        # Construct a json representation of a SecretGroupPatch model
        secret_group_patch_model_json = {}
        secret_group_patch_model_json['name'] = 'my-secret-group'
        secret_group_patch_model_json['description'] = 'Extended description for this group.'

        # Construct a model instance of SecretGroupPatch by calling from_dict on the json representation
        secret_group_patch_model = SecretGroupPatch.from_dict(secret_group_patch_model_json)
        assert secret_group_patch_model != False

        # Construct a model instance of SecretGroupPatch by calling from_dict on the json representation
        secret_group_patch_model_dict = SecretGroupPatch.from_dict(secret_group_patch_model_json).__dict__
        secret_group_patch_model2 = SecretGroupPatch(**secret_group_patch_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_patch_model == secret_group_patch_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_patch_model_json2 = secret_group_patch_model.to_dict()
        assert secret_group_patch_model_json2 == secret_group_patch_model_json


class TestModel_SecretLock:
    """
    Test Class for SecretLock
    """

    def test_secret_lock_serialization(self):
        """
        Test serialization/deserialization for SecretLock
        """

        # Construct a json representation of a SecretLock model
        secret_lock_model_json = {}
        secret_lock_model_json['name'] = 'lock-example'
        secret_lock_model_json['description'] = 'testString'
        secret_lock_model_json['attributes'] = {'key': 'value'}
        secret_lock_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_lock_model_json['secret_group_id'] = 'default'
        secret_lock_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model_json['secret_version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model_json['secret_version_alias'] = 'current'

        # Construct a model instance of SecretLock by calling from_dict on the json representation
        secret_lock_model = SecretLock.from_dict(secret_lock_model_json)
        assert secret_lock_model != False

        # Construct a model instance of SecretLock by calling from_dict on the json representation
        secret_lock_model_dict = SecretLock.from_dict(secret_lock_model_json).__dict__
        secret_lock_model2 = SecretLock(**secret_lock_model_dict)

        # Verify the model instances are equivalent
        assert secret_lock_model == secret_lock_model2

        # Convert model instance back to dict and verify no loss of data
        secret_lock_model_json2 = secret_lock_model.to_dict()
        assert secret_lock_model_json2 == secret_lock_model_json


class TestModel_SecretLockPrototype:
    """
    Test Class for SecretLockPrototype
    """

    def test_secret_lock_prototype_serialization(self):
        """
        Test serialization/deserialization for SecretLockPrototype
        """

        # Construct a json representation of a SecretLockPrototype model
        secret_lock_prototype_model_json = {}
        secret_lock_prototype_model_json['name'] = 'lock-example'
        secret_lock_prototype_model_json['description'] = 'testString'
        secret_lock_prototype_model_json['attributes'] = {'key': 'value'}

        # Construct a model instance of SecretLockPrototype by calling from_dict on the json representation
        secret_lock_prototype_model = SecretLockPrototype.from_dict(secret_lock_prototype_model_json)
        assert secret_lock_prototype_model != False

        # Construct a model instance of SecretLockPrototype by calling from_dict on the json representation
        secret_lock_prototype_model_dict = SecretLockPrototype.from_dict(secret_lock_prototype_model_json).__dict__
        secret_lock_prototype_model2 = SecretLockPrototype(**secret_lock_prototype_model_dict)

        # Verify the model instances are equivalent
        assert secret_lock_prototype_model == secret_lock_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        secret_lock_prototype_model_json2 = secret_lock_prototype_model.to_dict()
        assert secret_lock_prototype_model_json2 == secret_lock_prototype_model_json


class TestModel_SecretLocks:
    """
    Test Class for SecretLocks
    """

    def test_secret_locks_serialization(self):
        """
        Test serialization/deserialization for SecretLocks
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_version_locks_model = {}  # SecretVersionLocks
        secret_version_locks_model['version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_version_locks_model['version_alias'] = 'current'
        secret_version_locks_model['locks'] = ['lock-example-1', 'lock-example-2']
        secret_version_locks_model['payload_available'] = True

        # Construct a json representation of a SecretLocks model
        secret_locks_model_json = {}
        secret_locks_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_locks_model_json['secret_group_id'] = 'default'
        secret_locks_model_json['secret_type'] = 'arbitrary'
        secret_locks_model_json['versions'] = [secret_version_locks_model]

        # Construct a model instance of SecretLocks by calling from_dict on the json representation
        secret_locks_model = SecretLocks.from_dict(secret_locks_model_json)
        assert secret_locks_model != False

        # Construct a model instance of SecretLocks by calling from_dict on the json representation
        secret_locks_model_dict = SecretLocks.from_dict(secret_locks_model_json).__dict__
        secret_locks_model2 = SecretLocks(**secret_locks_model_dict)

        # Verify the model instances are equivalent
        assert secret_locks_model == secret_locks_model2

        # Convert model instance back to dict and verify no loss of data
        secret_locks_model_json2 = secret_locks_model.to_dict()
        assert secret_locks_model_json2 == secret_locks_model_json


class TestModel_SecretLocksPaginatedCollection:
    """
    Test Class for SecretLocksPaginatedCollection
    """

    def test_secret_locks_paginated_collection_serialization(self):
        """
        Test serialization/deserialization for SecretLocksPaginatedCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        paginated_collection_first_model = {}  # PaginatedCollectionFirst
        paginated_collection_first_model['href'] = 'testString'

        paginated_collection_next_model = {}  # PaginatedCollectionNext
        paginated_collection_next_model['href'] = 'testString'

        paginated_collection_previous_model = {}  # PaginatedCollectionPrevious
        paginated_collection_previous_model['href'] = 'testString'

        paginated_collection_last_model = {}  # PaginatedCollectionLast
        paginated_collection_last_model['href'] = 'testString'

        secret_lock_model = {}  # SecretLock
        secret_lock_model['name'] = 'lock-example'
        secret_lock_model['description'] = 'testString'
        secret_lock_model['attributes'] = {'key': 'value'}
        secret_lock_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model['updated_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_lock_model['secret_group_id'] = 'default'
        secret_lock_model['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model['secret_version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model['secret_version_alias'] = 'current'

        # Construct a json representation of a SecretLocksPaginatedCollection model
        secret_locks_paginated_collection_model_json = {}
        secret_locks_paginated_collection_model_json['total_count'] = 0
        secret_locks_paginated_collection_model_json['limit'] = 25
        secret_locks_paginated_collection_model_json['offset'] = 25
        secret_locks_paginated_collection_model_json['first'] = paginated_collection_first_model
        secret_locks_paginated_collection_model_json['next'] = paginated_collection_next_model
        secret_locks_paginated_collection_model_json['previous'] = paginated_collection_previous_model
        secret_locks_paginated_collection_model_json['last'] = paginated_collection_last_model
        secret_locks_paginated_collection_model_json['locks'] = [secret_lock_model]

        # Construct a model instance of SecretLocksPaginatedCollection by calling from_dict on the json representation
        secret_locks_paginated_collection_model = SecretLocksPaginatedCollection.from_dict(
            secret_locks_paginated_collection_model_json)
        assert secret_locks_paginated_collection_model != False

        # Construct a model instance of SecretLocksPaginatedCollection by calling from_dict on the json representation
        secret_locks_paginated_collection_model_dict = SecretLocksPaginatedCollection.from_dict(
            secret_locks_paginated_collection_model_json).__dict__
        secret_locks_paginated_collection_model2 = SecretLocksPaginatedCollection(
            **secret_locks_paginated_collection_model_dict)

        # Verify the model instances are equivalent
        assert secret_locks_paginated_collection_model == secret_locks_paginated_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secret_locks_paginated_collection_model_json2 = secret_locks_paginated_collection_model.to_dict()
        assert secret_locks_paginated_collection_model_json2 == secret_locks_paginated_collection_model_json


class TestModel_SecretMetadataPaginatedCollection:
    """
    Test Class for SecretMetadataPaginatedCollection
    """

    def test_secret_metadata_paginated_collection_serialization(self):
        """
        Test serialization/deserialization for SecretMetadataPaginatedCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        paginated_collection_first_model = {}  # PaginatedCollectionFirst
        paginated_collection_first_model['href'] = 'testString'

        paginated_collection_next_model = {}  # PaginatedCollectionNext
        paginated_collection_next_model['href'] = 'testString'

        paginated_collection_previous_model = {}  # PaginatedCollectionPrevious
        paginated_collection_previous_model['href'] = 'testString'

        paginated_collection_last_model = {}  # PaginatedCollectionLast
        paginated_collection_last_model['href'] = 'testString'

        secret_metadata_model = {}  # ArbitrarySecretMetadata
        secret_metadata_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_metadata_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_metadata_model['crn'] = 'testString'
        secret_metadata_model['custom_metadata'] = {'key': 'value'}
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_metadata_model['labels'] = ['my-label']
        secret_metadata_model['secret_group_id'] = 'default'
        secret_metadata_model['secret_type'] = 'arbitrary'
        secret_metadata_model['updated_at'] = '2022-04-12T23:20:50.520000Z'
        secret_metadata_model['versions_total'] = 0
        secret_metadata_model['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a json representation of a SecretMetadataPaginatedCollection model
        secret_metadata_paginated_collection_model_json = {}
        secret_metadata_paginated_collection_model_json['total_count'] = 0
        secret_metadata_paginated_collection_model_json['limit'] = 25
        secret_metadata_paginated_collection_model_json['offset'] = 25
        secret_metadata_paginated_collection_model_json['first'] = paginated_collection_first_model
        secret_metadata_paginated_collection_model_json['next'] = paginated_collection_next_model
        secret_metadata_paginated_collection_model_json['previous'] = paginated_collection_previous_model
        secret_metadata_paginated_collection_model_json['last'] = paginated_collection_last_model
        secret_metadata_paginated_collection_model_json['secrets'] = [secret_metadata_model]

        # Construct a model instance of SecretMetadataPaginatedCollection by calling from_dict on the json representation
        secret_metadata_paginated_collection_model = SecretMetadataPaginatedCollection.from_dict(
            secret_metadata_paginated_collection_model_json)
        assert secret_metadata_paginated_collection_model != False

        # Construct a model instance of SecretMetadataPaginatedCollection by calling from_dict on the json representation
        secret_metadata_paginated_collection_model_dict = SecretMetadataPaginatedCollection.from_dict(
            secret_metadata_paginated_collection_model_json).__dict__
        secret_metadata_paginated_collection_model2 = SecretMetadataPaginatedCollection(
            **secret_metadata_paginated_collection_model_dict)

        # Verify the model instances are equivalent
        assert secret_metadata_paginated_collection_model == secret_metadata_paginated_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secret_metadata_paginated_collection_model_json2 = secret_metadata_paginated_collection_model.to_dict()
        assert secret_metadata_paginated_collection_model_json2 == secret_metadata_paginated_collection_model_json


class TestModel_SecretVersionLocks:
    """
    Test Class for SecretVersionLocks
    """

    def test_secret_version_locks_serialization(self):
        """
        Test serialization/deserialization for SecretVersionLocks
        """

        # Construct a json representation of a SecretVersionLocks model
        secret_version_locks_model_json = {}
        secret_version_locks_model_json['version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_version_locks_model_json['version_alias'] = 'current'
        secret_version_locks_model_json['locks'] = ['lock-example-1', 'lock-example-2']
        secret_version_locks_model_json['payload_available'] = True

        # Construct a model instance of SecretVersionLocks by calling from_dict on the json representation
        secret_version_locks_model = SecretVersionLocks.from_dict(secret_version_locks_model_json)
        assert secret_version_locks_model != False

        # Construct a model instance of SecretVersionLocks by calling from_dict on the json representation
        secret_version_locks_model_dict = SecretVersionLocks.from_dict(secret_version_locks_model_json).__dict__
        secret_version_locks_model2 = SecretVersionLocks(**secret_version_locks_model_dict)

        # Verify the model instances are equivalent
        assert secret_version_locks_model == secret_version_locks_model2

        # Convert model instance back to dict and verify no loss of data
        secret_version_locks_model_json2 = secret_version_locks_model.to_dict()
        assert secret_version_locks_model_json2 == secret_version_locks_model_json


class TestModel_SecretVersionLocksPaginatedCollection:
    """
    Test Class for SecretVersionLocksPaginatedCollection
    """

    def test_secret_version_locks_paginated_collection_serialization(self):
        """
        Test serialization/deserialization for SecretVersionLocksPaginatedCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        paginated_collection_first_model = {}  # PaginatedCollectionFirst
        paginated_collection_first_model['href'] = 'testString'

        paginated_collection_next_model = {}  # PaginatedCollectionNext
        paginated_collection_next_model['href'] = 'testString'

        paginated_collection_previous_model = {}  # PaginatedCollectionPrevious
        paginated_collection_previous_model['href'] = 'testString'

        paginated_collection_last_model = {}  # PaginatedCollectionLast
        paginated_collection_last_model['href'] = 'testString'

        secret_lock_model = {}  # SecretLock
        secret_lock_model['name'] = 'lock-example'
        secret_lock_model['description'] = 'testString'
        secret_lock_model['attributes'] = {'key': 'value'}
        secret_lock_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model['updated_at'] = '2022-04-12T23:20:50.520000Z'
        secret_lock_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_lock_model['secret_group_id'] = 'default'
        secret_lock_model['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model['secret_version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_lock_model['secret_version_alias'] = 'current'

        # Construct a json representation of a SecretVersionLocksPaginatedCollection model
        secret_version_locks_paginated_collection_model_json = {}
        secret_version_locks_paginated_collection_model_json['total_count'] = 0
        secret_version_locks_paginated_collection_model_json['limit'] = 25
        secret_version_locks_paginated_collection_model_json['offset'] = 25
        secret_version_locks_paginated_collection_model_json['first'] = paginated_collection_first_model
        secret_version_locks_paginated_collection_model_json['next'] = paginated_collection_next_model
        secret_version_locks_paginated_collection_model_json['previous'] = paginated_collection_previous_model
        secret_version_locks_paginated_collection_model_json['last'] = paginated_collection_last_model
        secret_version_locks_paginated_collection_model_json['locks'] = [secret_lock_model]

        # Construct a model instance of SecretVersionLocksPaginatedCollection by calling from_dict on the json representation
        secret_version_locks_paginated_collection_model = SecretVersionLocksPaginatedCollection.from_dict(
            secret_version_locks_paginated_collection_model_json)
        assert secret_version_locks_paginated_collection_model != False

        # Construct a model instance of SecretVersionLocksPaginatedCollection by calling from_dict on the json representation
        secret_version_locks_paginated_collection_model_dict = SecretVersionLocksPaginatedCollection.from_dict(
            secret_version_locks_paginated_collection_model_json).__dict__
        secret_version_locks_paginated_collection_model2 = SecretVersionLocksPaginatedCollection(
            **secret_version_locks_paginated_collection_model_dict)

        # Verify the model instances are equivalent
        assert secret_version_locks_paginated_collection_model == secret_version_locks_paginated_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secret_version_locks_paginated_collection_model_json2 = secret_version_locks_paginated_collection_model.to_dict()
        assert secret_version_locks_paginated_collection_model_json2 == secret_version_locks_paginated_collection_model_json


class TestModel_SecretVersionMetadataCollection:
    """
    Test Class for SecretVersionMetadataCollection
    """

    def test_secret_version_metadata_collection_serialization(self):
        """
        Test serialization/deserialization for SecretVersionMetadataCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_version_metadata_model = {}  # ArbitrarySecretVersionMetadata
        secret_version_metadata_model['auto_rotated'] = True
        secret_version_metadata_model['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        secret_version_metadata_model['created_at'] = '2022-04-12T23:20:50.520000Z'
        secret_version_metadata_model['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_version_metadata_model['secret_type'] = 'arbitrary'
        secret_version_metadata_model['secret_group_id'] = 'default'
        secret_version_metadata_model['payload_available'] = True
        secret_version_metadata_model['alias'] = 'current'
        secret_version_metadata_model['version_custom_metadata'] = {'key': 'value'}
        secret_version_metadata_model['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_version_metadata_model['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a json representation of a SecretVersionMetadataCollection model
        secret_version_metadata_collection_model_json = {}
        secret_version_metadata_collection_model_json['versions'] = [secret_version_metadata_model]
        secret_version_metadata_collection_model_json['total_count'] = 0

        # Construct a model instance of SecretVersionMetadataCollection by calling from_dict on the json representation
        secret_version_metadata_collection_model = SecretVersionMetadataCollection.from_dict(
            secret_version_metadata_collection_model_json)
        assert secret_version_metadata_collection_model != False

        # Construct a model instance of SecretVersionMetadataCollection by calling from_dict on the json representation
        secret_version_metadata_collection_model_dict = SecretVersionMetadataCollection.from_dict(
            secret_version_metadata_collection_model_json).__dict__
        secret_version_metadata_collection_model2 = SecretVersionMetadataCollection(
            **secret_version_metadata_collection_model_dict)

        # Verify the model instances are equivalent
        assert secret_version_metadata_collection_model == secret_version_metadata_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secret_version_metadata_collection_model_json2 = secret_version_metadata_collection_model.to_dict()
        assert secret_version_metadata_collection_model_json2 == secret_version_metadata_collection_model_json


class TestModel_SecretVersionMetadataPatch:
    """
    Test Class for SecretVersionMetadataPatch
    """

    def test_secret_version_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for SecretVersionMetadataPatch
        """

        # Construct a json representation of a SecretVersionMetadataPatch model
        secret_version_metadata_patch_model_json = {}
        secret_version_metadata_patch_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of SecretVersionMetadataPatch by calling from_dict on the json representation
        secret_version_metadata_patch_model = SecretVersionMetadataPatch.from_dict(
            secret_version_metadata_patch_model_json)
        assert secret_version_metadata_patch_model != False

        # Construct a model instance of SecretVersionMetadataPatch by calling from_dict on the json representation
        secret_version_metadata_patch_model_dict = SecretVersionMetadataPatch.from_dict(
            secret_version_metadata_patch_model_json).__dict__
        secret_version_metadata_patch_model2 = SecretVersionMetadataPatch(**secret_version_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert secret_version_metadata_patch_model == secret_version_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        secret_version_metadata_patch_model_json2 = secret_version_metadata_patch_model.to_dict()
        assert secret_version_metadata_patch_model_json2 == secret_version_metadata_patch_model_json


class TestModel_SecretsLocksPaginatedCollection:
    """
    Test Class for SecretsLocksPaginatedCollection
    """

    def test_secrets_locks_paginated_collection_serialization(self):
        """
        Test serialization/deserialization for SecretsLocksPaginatedCollection
        """

        # Construct dict forms of any model objects needed in order to build this model.

        paginated_collection_first_model = {}  # PaginatedCollectionFirst
        paginated_collection_first_model['href'] = 'testString'

        paginated_collection_next_model = {}  # PaginatedCollectionNext
        paginated_collection_next_model['href'] = 'testString'

        paginated_collection_previous_model = {}  # PaginatedCollectionPrevious
        paginated_collection_previous_model['href'] = 'testString'

        paginated_collection_last_model = {}  # PaginatedCollectionLast
        paginated_collection_last_model['href'] = 'testString'

        secret_version_locks_model = {}  # SecretVersionLocks
        secret_version_locks_model['version_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_version_locks_model['version_alias'] = 'current'
        secret_version_locks_model['locks'] = ['lock-example-1', 'lock-example-2']
        secret_version_locks_model['payload_available'] = True

        secret_locks_model = {}  # SecretLocks
        secret_locks_model['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        secret_locks_model['secret_group_id'] = 'default'
        secret_locks_model['secret_type'] = 'arbitrary'
        secret_locks_model['versions'] = [secret_version_locks_model]

        # Construct a json representation of a SecretsLocksPaginatedCollection model
        secrets_locks_paginated_collection_model_json = {}
        secrets_locks_paginated_collection_model_json['total_count'] = 0
        secrets_locks_paginated_collection_model_json['limit'] = 25
        secrets_locks_paginated_collection_model_json['offset'] = 25
        secrets_locks_paginated_collection_model_json['first'] = paginated_collection_first_model
        secrets_locks_paginated_collection_model_json['next'] = paginated_collection_next_model
        secrets_locks_paginated_collection_model_json['previous'] = paginated_collection_previous_model
        secrets_locks_paginated_collection_model_json['last'] = paginated_collection_last_model
        secrets_locks_paginated_collection_model_json['secrets_locks'] = [secret_locks_model]

        # Construct a model instance of SecretsLocksPaginatedCollection by calling from_dict on the json representation
        secrets_locks_paginated_collection_model = SecretsLocksPaginatedCollection.from_dict(
            secrets_locks_paginated_collection_model_json)
        assert secrets_locks_paginated_collection_model != False

        # Construct a model instance of SecretsLocksPaginatedCollection by calling from_dict on the json representation
        secrets_locks_paginated_collection_model_dict = SecretsLocksPaginatedCollection.from_dict(
            secrets_locks_paginated_collection_model_json).__dict__
        secrets_locks_paginated_collection_model2 = SecretsLocksPaginatedCollection(
            **secrets_locks_paginated_collection_model_dict)

        # Verify the model instances are equivalent
        assert secrets_locks_paginated_collection_model == secrets_locks_paginated_collection_model2

        # Convert model instance back to dict and verify no loss of data
        secrets_locks_paginated_collection_model_json2 = secrets_locks_paginated_collection_model.to_dict()
        assert secrets_locks_paginated_collection_model_json2 == secrets_locks_paginated_collection_model_json


class TestModel_ServiceCredentialsResourceKey:
    """
    Test Class for ServiceCredentialsResourceKey
    """

    def test_service_credentials_resource_key_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsResourceKey
        """

        # Construct a json representation of a ServiceCredentialsResourceKey model
        service_credentials_resource_key_model_json = {}

        # Construct a model instance of ServiceCredentialsResourceKey by calling from_dict on the json representation
        service_credentials_resource_key_model = ServiceCredentialsResourceKey.from_dict(
            service_credentials_resource_key_model_json)
        assert service_credentials_resource_key_model != False

        # Construct a model instance of ServiceCredentialsResourceKey by calling from_dict on the json representation
        service_credentials_resource_key_model_dict = ServiceCredentialsResourceKey.from_dict(
            service_credentials_resource_key_model_json).__dict__
        service_credentials_resource_key_model2 = ServiceCredentialsResourceKey(
            **service_credentials_resource_key_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_resource_key_model == service_credentials_resource_key_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_resource_key_model_json2 = service_credentials_resource_key_model.to_dict()
        assert service_credentials_resource_key_model_json2 == service_credentials_resource_key_model_json


class TestModel_ServiceCredentialsSecretCredentials:
    """
    Test Class for ServiceCredentialsSecretCredentials
    """

    def test_service_credentials_secret_credentials_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretCredentials
        """

        # Construct a json representation of a ServiceCredentialsSecretCredentials model
        service_credentials_secret_credentials_model_json = {}
        service_credentials_secret_credentials_model_json['foo'] = 'testString'

        # Construct a model instance of ServiceCredentialsSecretCredentials by calling from_dict on the json representation
        service_credentials_secret_credentials_model = ServiceCredentialsSecretCredentials.from_dict(
            service_credentials_secret_credentials_model_json)
        assert service_credentials_secret_credentials_model != False

        # Construct a model instance of ServiceCredentialsSecretCredentials by calling from_dict on the json representation
        service_credentials_secret_credentials_model_dict = ServiceCredentialsSecretCredentials.from_dict(
            service_credentials_secret_credentials_model_json).__dict__
        service_credentials_secret_credentials_model2 = ServiceCredentialsSecretCredentials(
            **service_credentials_secret_credentials_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_credentials_model == service_credentials_secret_credentials_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_credentials_model_json2 = service_credentials_secret_credentials_model.to_dict()
        assert service_credentials_secret_credentials_model_json2 == service_credentials_secret_credentials_model_json

        # Test get_properties and set_properties methods.
        service_credentials_secret_credentials_model.set_properties({})
        actual_dict = service_credentials_secret_credentials_model.get_properties()
        assert actual_dict == {}

        expected_dict = {'foo': 'testString'}
        service_credentials_secret_credentials_model.set_properties(expected_dict)
        actual_dict = service_credentials_secret_credentials_model.get_properties()
        assert actual_dict.keys() == expected_dict.keys()


class TestModel_ServiceCredentialsSecretSourceService:
    """
    Test Class for ServiceCredentialsSecretSourceService
    """

    def test_service_credentials_secret_source_service_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretSourceService
        """

        # Construct dict forms of any model objects needed in order to build this model.

        service_credentials_source_service_instance_model = {}  # ServiceCredentialsSourceServiceInstance
        service_credentials_source_service_instance_model['crn'] = 'testString'

        service_credentials_source_service_parameters_model = {}  # ServiceCredentialsSourceServiceParameters
        service_credentials_source_service_parameters_model['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model['foo'] = 'testString'

        service_credentials_source_service_role_model = {}  # ServiceCredentialsSourceServiceRole
        service_credentials_source_service_role_model['crn'] = 'testString'

        # Construct a json representation of a ServiceCredentialsSecretSourceService model
        service_credentials_secret_source_service_model_json = {}
        service_credentials_secret_source_service_model_json[
            'instance'] = service_credentials_source_service_instance_model
        service_credentials_secret_source_service_model_json[
            'parameters'] = service_credentials_source_service_parameters_model
        service_credentials_secret_source_service_model_json['role'] = service_credentials_source_service_role_model

        # Construct a model instance of ServiceCredentialsSecretSourceService by calling from_dict on the json representation
        service_credentials_secret_source_service_model = ServiceCredentialsSecretSourceService.from_dict(
            service_credentials_secret_source_service_model_json)
        assert service_credentials_secret_source_service_model != False

        # Construct a model instance of ServiceCredentialsSecretSourceService by calling from_dict on the json representation
        service_credentials_secret_source_service_model_dict = ServiceCredentialsSecretSourceService.from_dict(
            service_credentials_secret_source_service_model_json).__dict__
        service_credentials_secret_source_service_model2 = ServiceCredentialsSecretSourceService(
            **service_credentials_secret_source_service_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_source_service_model == service_credentials_secret_source_service_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_source_service_model_json2 = service_credentials_secret_source_service_model.to_dict()
        assert service_credentials_secret_source_service_model_json2 == service_credentials_secret_source_service_model_json


class TestModel_ServiceCredentialsSecretSourceServiceRO:
    """
    Test Class for ServiceCredentialsSecretSourceServiceRO
    """

    def test_service_credentials_secret_source_service_ro_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretSourceServiceRO
        """

        # Construct dict forms of any model objects needed in order to build this model.

        service_credentials_source_service_instance_model = {}  # ServiceCredentialsSourceServiceInstance
        service_credentials_source_service_instance_model['crn'] = 'testString'

        service_credentials_source_service_parameters_model = {}  # ServiceCredentialsSourceServiceParameters
        service_credentials_source_service_parameters_model['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model['foo'] = 'testString'

        service_credentials_source_service_role_model = {}  # ServiceCredentialsSourceServiceRole
        service_credentials_source_service_role_model['crn'] = 'testString'

        service_credentials_source_service_iam_apikey_model = {}  # ServiceCredentialsSourceServiceIamApikey

        service_credentials_source_service_iam_role_model = {}  # ServiceCredentialsSourceServiceIamRole

        service_credentials_source_service_iam_serviceid_model = {}  # ServiceCredentialsSourceServiceIamServiceid

        service_credentials_source_service_iam_model = {}  # ServiceCredentialsSourceServiceIam
        service_credentials_source_service_iam_model['apikey'] = service_credentials_source_service_iam_apikey_model
        service_credentials_source_service_iam_model['role'] = service_credentials_source_service_iam_role_model
        service_credentials_source_service_iam_model[
            'serviceid'] = service_credentials_source_service_iam_serviceid_model

        service_credentials_resource_key_model = {}  # ServiceCredentialsResourceKey

        # Construct a json representation of a ServiceCredentialsSecretSourceServiceRO model
        service_credentials_secret_source_service_ro_model_json = {}
        service_credentials_secret_source_service_ro_model_json[
            'instance'] = service_credentials_source_service_instance_model
        service_credentials_secret_source_service_ro_model_json[
            'parameters'] = service_credentials_source_service_parameters_model
        service_credentials_secret_source_service_ro_model_json['role'] = service_credentials_source_service_role_model
        service_credentials_secret_source_service_ro_model_json['iam'] = service_credentials_source_service_iam_model
        service_credentials_secret_source_service_ro_model_json['resource_key'] = service_credentials_resource_key_model

        # Construct a model instance of ServiceCredentialsSecretSourceServiceRO by calling from_dict on the json representation
        service_credentials_secret_source_service_ro_model = ServiceCredentialsSecretSourceServiceRO.from_dict(
            service_credentials_secret_source_service_ro_model_json)
        assert service_credentials_secret_source_service_ro_model != False

        # Construct a model instance of ServiceCredentialsSecretSourceServiceRO by calling from_dict on the json representation
        service_credentials_secret_source_service_ro_model_dict = ServiceCredentialsSecretSourceServiceRO.from_dict(
            service_credentials_secret_source_service_ro_model_json).__dict__
        service_credentials_secret_source_service_ro_model2 = ServiceCredentialsSecretSourceServiceRO(
            **service_credentials_secret_source_service_ro_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_source_service_ro_model == service_credentials_secret_source_service_ro_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_source_service_ro_model_json2 = service_credentials_secret_source_service_ro_model.to_dict()
        assert service_credentials_secret_source_service_ro_model_json2 == service_credentials_secret_source_service_ro_model_json


class TestModel_ServiceCredentialsSourceServiceIam:
    """
    Test Class for ServiceCredentialsSourceServiceIam
    """

    def test_service_credentials_source_service_iam_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceIam
        """

        # Construct dict forms of any model objects needed in order to build this model.

        service_credentials_source_service_iam_apikey_model = {}  # ServiceCredentialsSourceServiceIamApikey

        service_credentials_source_service_iam_role_model = {}  # ServiceCredentialsSourceServiceIamRole

        service_credentials_source_service_iam_serviceid_model = {}  # ServiceCredentialsSourceServiceIamServiceid

        # Construct a json representation of a ServiceCredentialsSourceServiceIam model
        service_credentials_source_service_iam_model_json = {}
        service_credentials_source_service_iam_model_json[
            'apikey'] = service_credentials_source_service_iam_apikey_model
        service_credentials_source_service_iam_model_json['role'] = service_credentials_source_service_iam_role_model
        service_credentials_source_service_iam_model_json[
            'serviceid'] = service_credentials_source_service_iam_serviceid_model

        # Construct a model instance of ServiceCredentialsSourceServiceIam by calling from_dict on the json representation
        service_credentials_source_service_iam_model = ServiceCredentialsSourceServiceIam.from_dict(
            service_credentials_source_service_iam_model_json)
        assert service_credentials_source_service_iam_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceIam by calling from_dict on the json representation
        service_credentials_source_service_iam_model_dict = ServiceCredentialsSourceServiceIam.from_dict(
            service_credentials_source_service_iam_model_json).__dict__
        service_credentials_source_service_iam_model2 = ServiceCredentialsSourceServiceIam(
            **service_credentials_source_service_iam_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_iam_model == service_credentials_source_service_iam_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_iam_model_json2 = service_credentials_source_service_iam_model.to_dict()
        assert service_credentials_source_service_iam_model_json2 == service_credentials_source_service_iam_model_json


class TestModel_ServiceCredentialsSourceServiceIamApikey:
    """
    Test Class for ServiceCredentialsSourceServiceIamApikey
    """

    def test_service_credentials_source_service_iam_apikey_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceIamApikey
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceIamApikey model
        service_credentials_source_service_iam_apikey_model_json = {}

        # Construct a model instance of ServiceCredentialsSourceServiceIamApikey by calling from_dict on the json representation
        service_credentials_source_service_iam_apikey_model = ServiceCredentialsSourceServiceIamApikey.from_dict(
            service_credentials_source_service_iam_apikey_model_json)
        assert service_credentials_source_service_iam_apikey_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceIamApikey by calling from_dict on the json representation
        service_credentials_source_service_iam_apikey_model_dict = ServiceCredentialsSourceServiceIamApikey.from_dict(
            service_credentials_source_service_iam_apikey_model_json).__dict__
        service_credentials_source_service_iam_apikey_model2 = ServiceCredentialsSourceServiceIamApikey(
            **service_credentials_source_service_iam_apikey_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_iam_apikey_model == service_credentials_source_service_iam_apikey_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_iam_apikey_model_json2 = service_credentials_source_service_iam_apikey_model.to_dict()
        assert service_credentials_source_service_iam_apikey_model_json2 == service_credentials_source_service_iam_apikey_model_json


class TestModel_ServiceCredentialsSourceServiceIamRole:
    """
    Test Class for ServiceCredentialsSourceServiceIamRole
    """

    def test_service_credentials_source_service_iam_role_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceIamRole
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceIamRole model
        service_credentials_source_service_iam_role_model_json = {}

        # Construct a model instance of ServiceCredentialsSourceServiceIamRole by calling from_dict on the json representation
        service_credentials_source_service_iam_role_model = ServiceCredentialsSourceServiceIamRole.from_dict(
            service_credentials_source_service_iam_role_model_json)
        assert service_credentials_source_service_iam_role_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceIamRole by calling from_dict on the json representation
        service_credentials_source_service_iam_role_model_dict = ServiceCredentialsSourceServiceIamRole.from_dict(
            service_credentials_source_service_iam_role_model_json).__dict__
        service_credentials_source_service_iam_role_model2 = ServiceCredentialsSourceServiceIamRole(
            **service_credentials_source_service_iam_role_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_iam_role_model == service_credentials_source_service_iam_role_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_iam_role_model_json2 = service_credentials_source_service_iam_role_model.to_dict()
        assert service_credentials_source_service_iam_role_model_json2 == service_credentials_source_service_iam_role_model_json


class TestModel_ServiceCredentialsSourceServiceIamServiceid:
    """
    Test Class for ServiceCredentialsSourceServiceIamServiceid
    """

    def test_service_credentials_source_service_iam_serviceid_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceIamServiceid
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceIamServiceid model
        service_credentials_source_service_iam_serviceid_model_json = {}

        # Construct a model instance of ServiceCredentialsSourceServiceIamServiceid by calling from_dict on the json representation
        service_credentials_source_service_iam_serviceid_model = ServiceCredentialsSourceServiceIamServiceid.from_dict(
            service_credentials_source_service_iam_serviceid_model_json)
        assert service_credentials_source_service_iam_serviceid_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceIamServiceid by calling from_dict on the json representation
        service_credentials_source_service_iam_serviceid_model_dict = ServiceCredentialsSourceServiceIamServiceid.from_dict(
            service_credentials_source_service_iam_serviceid_model_json).__dict__
        service_credentials_source_service_iam_serviceid_model2 = ServiceCredentialsSourceServiceIamServiceid(
            **service_credentials_source_service_iam_serviceid_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_iam_serviceid_model == service_credentials_source_service_iam_serviceid_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_iam_serviceid_model_json2 = service_credentials_source_service_iam_serviceid_model.to_dict()
        assert service_credentials_source_service_iam_serviceid_model_json2 == service_credentials_source_service_iam_serviceid_model_json


class TestModel_ServiceCredentialsSourceServiceInstance:
    """
    Test Class for ServiceCredentialsSourceServiceInstance
    """

    def test_service_credentials_source_service_instance_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceInstance
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceInstance model
        service_credentials_source_service_instance_model_json = {}
        service_credentials_source_service_instance_model_json['crn'] = 'testString'

        # Construct a model instance of ServiceCredentialsSourceServiceInstance by calling from_dict on the json representation
        service_credentials_source_service_instance_model = ServiceCredentialsSourceServiceInstance.from_dict(
            service_credentials_source_service_instance_model_json)
        assert service_credentials_source_service_instance_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceInstance by calling from_dict on the json representation
        service_credentials_source_service_instance_model_dict = ServiceCredentialsSourceServiceInstance.from_dict(
            service_credentials_source_service_instance_model_json).__dict__
        service_credentials_source_service_instance_model2 = ServiceCredentialsSourceServiceInstance(
            **service_credentials_source_service_instance_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_instance_model == service_credentials_source_service_instance_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_instance_model_json2 = service_credentials_source_service_instance_model.to_dict()
        assert service_credentials_source_service_instance_model_json2 == service_credentials_source_service_instance_model_json


class TestModel_ServiceCredentialsSourceServiceParameters:
    """
    Test Class for ServiceCredentialsSourceServiceParameters
    """

    def test_service_credentials_source_service_parameters_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceParameters
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceParameters model
        service_credentials_source_service_parameters_model_json = {}
        service_credentials_source_service_parameters_model_json['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model_json['foo'] = 'testString'

        # Construct a model instance of ServiceCredentialsSourceServiceParameters by calling from_dict on the json representation
        service_credentials_source_service_parameters_model = ServiceCredentialsSourceServiceParameters.from_dict(
            service_credentials_source_service_parameters_model_json)
        assert service_credentials_source_service_parameters_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceParameters by calling from_dict on the json representation
        service_credentials_source_service_parameters_model_dict = ServiceCredentialsSourceServiceParameters.from_dict(
            service_credentials_source_service_parameters_model_json).__dict__
        service_credentials_source_service_parameters_model2 = ServiceCredentialsSourceServiceParameters(
            **service_credentials_source_service_parameters_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_parameters_model == service_credentials_source_service_parameters_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_parameters_model_json2 = service_credentials_source_service_parameters_model.to_dict()
        assert service_credentials_source_service_parameters_model_json2 == service_credentials_source_service_parameters_model_json

        # Test get_properties and set_properties methods.
        service_credentials_source_service_parameters_model.set_properties({})
        actual_dict = service_credentials_source_service_parameters_model.get_properties()
        assert actual_dict == {}

        expected_dict = {'foo': 'testString'}
        service_credentials_source_service_parameters_model.set_properties(expected_dict)
        actual_dict = service_credentials_source_service_parameters_model.get_properties()
        assert actual_dict.keys() == expected_dict.keys()


class TestModel_ServiceCredentialsSourceServiceRole:
    """
    Test Class for ServiceCredentialsSourceServiceRole
    """

    def test_service_credentials_source_service_role_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSourceServiceRole
        """

        # Construct a json representation of a ServiceCredentialsSourceServiceRole model
        service_credentials_source_service_role_model_json = {}
        service_credentials_source_service_role_model_json['crn'] = 'testString'

        # Construct a model instance of ServiceCredentialsSourceServiceRole by calling from_dict on the json representation
        service_credentials_source_service_role_model = ServiceCredentialsSourceServiceRole.from_dict(
            service_credentials_source_service_role_model_json)
        assert service_credentials_source_service_role_model != False

        # Construct a model instance of ServiceCredentialsSourceServiceRole by calling from_dict on the json representation
        service_credentials_source_service_role_model_dict = ServiceCredentialsSourceServiceRole.from_dict(
            service_credentials_source_service_role_model_json).__dict__
        service_credentials_source_service_role_model2 = ServiceCredentialsSourceServiceRole(
            **service_credentials_source_service_role_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_source_service_role_model == service_credentials_source_service_role_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_source_service_role_model_json2 = service_credentials_source_service_role_model.to_dict()
        assert service_credentials_source_service_role_model_json2 == service_credentials_source_service_role_model_json


class TestModel_ArbitrarySecret:
    """
    Test Class for ArbitrarySecret
    """

    def test_arbitrary_secret_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecret
        """

        # Construct a json representation of a ArbitrarySecret model
        arbitrary_secret_model_json = {}
        arbitrary_secret_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        arbitrary_secret_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_model_json['crn'] = 'testString'
        arbitrary_secret_model_json['custom_metadata'] = {'key': 'value'}
        arbitrary_secret_model_json['description'] = 'Extended description for this secret.'
        arbitrary_secret_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_model_json['labels'] = ['my-label']
        arbitrary_secret_model_json['secret_group_id'] = 'default'
        arbitrary_secret_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_model_json['versions_total'] = 0
        arbitrary_secret_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        arbitrary_secret_model_json['payload'] = 'secret-credentials'

        # Construct a model instance of ArbitrarySecret by calling from_dict on the json representation
        arbitrary_secret_model = ArbitrarySecret.from_dict(arbitrary_secret_model_json)
        assert arbitrary_secret_model != False

        # Construct a model instance of ArbitrarySecret by calling from_dict on the json representation
        arbitrary_secret_model_dict = ArbitrarySecret.from_dict(arbitrary_secret_model_json).__dict__
        arbitrary_secret_model2 = ArbitrarySecret(**arbitrary_secret_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_model == arbitrary_secret_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_model_json2 = arbitrary_secret_model.to_dict()
        assert arbitrary_secret_model_json2 == arbitrary_secret_model_json


class TestModel_ArbitrarySecretMetadata:
    """
    Test Class for ArbitrarySecretMetadata
    """

    def test_arbitrary_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretMetadata
        """

        # Construct a json representation of a ArbitrarySecretMetadata model
        arbitrary_secret_metadata_model_json = {}
        arbitrary_secret_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        arbitrary_secret_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_metadata_model_json['crn'] = 'testString'
        arbitrary_secret_metadata_model_json['custom_metadata'] = {'key': 'value'}
        arbitrary_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        arbitrary_secret_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_metadata_model_json['labels'] = ['my-label']
        arbitrary_secret_metadata_model_json['secret_group_id'] = 'default'
        arbitrary_secret_metadata_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_metadata_model_json['versions_total'] = 0
        arbitrary_secret_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of ArbitrarySecretMetadata by calling from_dict on the json representation
        arbitrary_secret_metadata_model = ArbitrarySecretMetadata.from_dict(arbitrary_secret_metadata_model_json)
        assert arbitrary_secret_metadata_model != False

        # Construct a model instance of ArbitrarySecretMetadata by calling from_dict on the json representation
        arbitrary_secret_metadata_model_dict = ArbitrarySecretMetadata.from_dict(
            arbitrary_secret_metadata_model_json).__dict__
        arbitrary_secret_metadata_model2 = ArbitrarySecretMetadata(**arbitrary_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_metadata_model == arbitrary_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_metadata_model_json2 = arbitrary_secret_metadata_model.to_dict()
        assert arbitrary_secret_metadata_model_json2 == arbitrary_secret_metadata_model_json


class TestModel_ArbitrarySecretMetadataPatch:
    """
    Test Class for ArbitrarySecretMetadataPatch
    """

    def test_arbitrary_secret_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretMetadataPatch
        """

        # Construct a json representation of a ArbitrarySecretMetadataPatch model
        arbitrary_secret_metadata_patch_model_json = {}
        arbitrary_secret_metadata_patch_model_json['name'] = 'my-secret-example'
        arbitrary_secret_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        arbitrary_secret_metadata_patch_model_json['labels'] = ['my-label']
        arbitrary_secret_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        arbitrary_secret_metadata_patch_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of ArbitrarySecretMetadataPatch by calling from_dict on the json representation
        arbitrary_secret_metadata_patch_model = ArbitrarySecretMetadataPatch.from_dict(
            arbitrary_secret_metadata_patch_model_json)
        assert arbitrary_secret_metadata_patch_model != False

        # Construct a model instance of ArbitrarySecretMetadataPatch by calling from_dict on the json representation
        arbitrary_secret_metadata_patch_model_dict = ArbitrarySecretMetadataPatch.from_dict(
            arbitrary_secret_metadata_patch_model_json).__dict__
        arbitrary_secret_metadata_patch_model2 = ArbitrarySecretMetadataPatch(
            **arbitrary_secret_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_metadata_patch_model == arbitrary_secret_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_metadata_patch_model_json2 = arbitrary_secret_metadata_patch_model.to_dict()
        assert arbitrary_secret_metadata_patch_model_json2 == arbitrary_secret_metadata_patch_model_json


class TestModel_ArbitrarySecretPrototype:
    """
    Test Class for ArbitrarySecretPrototype
    """

    def test_arbitrary_secret_prototype_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretPrototype
        """

        # Construct a json representation of a ArbitrarySecretPrototype model
        arbitrary_secret_prototype_model_json = {}
        arbitrary_secret_prototype_model_json['custom_metadata'] = {'key': 'value'}
        arbitrary_secret_prototype_model_json['description'] = 'Extended description for this secret.'
        arbitrary_secret_prototype_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        arbitrary_secret_prototype_model_json['labels'] = ['my-label']
        arbitrary_secret_prototype_model_json['name'] = 'my-secret-example'
        arbitrary_secret_prototype_model_json['secret_group_id'] = 'default'
        arbitrary_secret_prototype_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_prototype_model_json['payload'] = 'secret-credentials'
        arbitrary_secret_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ArbitrarySecretPrototype by calling from_dict on the json representation
        arbitrary_secret_prototype_model = ArbitrarySecretPrototype.from_dict(arbitrary_secret_prototype_model_json)
        assert arbitrary_secret_prototype_model != False

        # Construct a model instance of ArbitrarySecretPrototype by calling from_dict on the json representation
        arbitrary_secret_prototype_model_dict = ArbitrarySecretPrototype.from_dict(
            arbitrary_secret_prototype_model_json).__dict__
        arbitrary_secret_prototype_model2 = ArbitrarySecretPrototype(**arbitrary_secret_prototype_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_prototype_model == arbitrary_secret_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_prototype_model_json2 = arbitrary_secret_prototype_model.to_dict()
        assert arbitrary_secret_prototype_model_json2 == arbitrary_secret_prototype_model_json


class TestModel_ArbitrarySecretVersion:
    """
    Test Class for ArbitrarySecretVersion
    """

    def test_arbitrary_secret_version_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretVersion
        """

        # Construct a json representation of a ArbitrarySecretVersion model
        arbitrary_secret_version_model_json = {}
        arbitrary_secret_version_model_json['auto_rotated'] = True
        arbitrary_secret_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        arbitrary_secret_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_version_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_version_model_json['secret_group_id'] = 'default'
        arbitrary_secret_version_model_json['payload_available'] = True
        arbitrary_secret_version_model_json['alias'] = 'current'
        arbitrary_secret_version_model_json['version_custom_metadata'] = {'key': 'value'}
        arbitrary_secret_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        arbitrary_secret_version_model_json['payload'] = 'secret-credentials'

        # Construct a model instance of ArbitrarySecretVersion by calling from_dict on the json representation
        arbitrary_secret_version_model = ArbitrarySecretVersion.from_dict(arbitrary_secret_version_model_json)
        assert arbitrary_secret_version_model != False

        # Construct a model instance of ArbitrarySecretVersion by calling from_dict on the json representation
        arbitrary_secret_version_model_dict = ArbitrarySecretVersion.from_dict(
            arbitrary_secret_version_model_json).__dict__
        arbitrary_secret_version_model2 = ArbitrarySecretVersion(**arbitrary_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_version_model == arbitrary_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_version_model_json2 = arbitrary_secret_version_model.to_dict()
        assert arbitrary_secret_version_model_json2 == arbitrary_secret_version_model_json


class TestModel_ArbitrarySecretVersionMetadata:
    """
    Test Class for ArbitrarySecretVersionMetadata
    """

    def test_arbitrary_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretVersionMetadata
        """

        # Construct a json representation of a ArbitrarySecretVersionMetadata model
        arbitrary_secret_version_metadata_model_json = {}
        arbitrary_secret_version_metadata_model_json['auto_rotated'] = True
        arbitrary_secret_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        arbitrary_secret_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        arbitrary_secret_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_version_metadata_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_version_metadata_model_json['secret_group_id'] = 'default'
        arbitrary_secret_version_metadata_model_json['payload_available'] = True
        arbitrary_secret_version_metadata_model_json['alias'] = 'current'
        arbitrary_secret_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        arbitrary_secret_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        arbitrary_secret_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of ArbitrarySecretVersionMetadata by calling from_dict on the json representation
        arbitrary_secret_version_metadata_model = ArbitrarySecretVersionMetadata.from_dict(
            arbitrary_secret_version_metadata_model_json)
        assert arbitrary_secret_version_metadata_model != False

        # Construct a model instance of ArbitrarySecretVersionMetadata by calling from_dict on the json representation
        arbitrary_secret_version_metadata_model_dict = ArbitrarySecretVersionMetadata.from_dict(
            arbitrary_secret_version_metadata_model_json).__dict__
        arbitrary_secret_version_metadata_model2 = ArbitrarySecretVersionMetadata(
            **arbitrary_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_version_metadata_model == arbitrary_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_version_metadata_model_json2 = arbitrary_secret_version_metadata_model.to_dict()
        assert arbitrary_secret_version_metadata_model_json2 == arbitrary_secret_version_metadata_model_json


class TestModel_ArbitrarySecretVersionPrototype:
    """
    Test Class for ArbitrarySecretVersionPrototype
    """

    def test_arbitrary_secret_version_prototype_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretVersionPrototype
        """

        # Construct a json representation of a ArbitrarySecretVersionPrototype model
        arbitrary_secret_version_prototype_model_json = {}
        arbitrary_secret_version_prototype_model_json['payload'] = 'secret-credentials'
        arbitrary_secret_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        arbitrary_secret_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ArbitrarySecretVersionPrototype by calling from_dict on the json representation
        arbitrary_secret_version_prototype_model = ArbitrarySecretVersionPrototype.from_dict(
            arbitrary_secret_version_prototype_model_json)
        assert arbitrary_secret_version_prototype_model != False

        # Construct a model instance of ArbitrarySecretVersionPrototype by calling from_dict on the json representation
        arbitrary_secret_version_prototype_model_dict = ArbitrarySecretVersionPrototype.from_dict(
            arbitrary_secret_version_prototype_model_json).__dict__
        arbitrary_secret_version_prototype_model2 = ArbitrarySecretVersionPrototype(
            **arbitrary_secret_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_version_prototype_model == arbitrary_secret_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_version_prototype_model_json2 = arbitrary_secret_version_prototype_model.to_dict()
        assert arbitrary_secret_version_prototype_model_json2 == arbitrary_secret_version_prototype_model_json


class TestModel_CommonRotationPolicy:
    """
    Test Class for CommonRotationPolicy
    """

    def test_common_rotation_policy_serialization(self):
        """
        Test serialization/deserialization for CommonRotationPolicy
        """

        # Construct a json representation of a CommonRotationPolicy model
        common_rotation_policy_model_json = {}
        common_rotation_policy_model_json['auto_rotate'] = True
        common_rotation_policy_model_json['interval'] = 1
        common_rotation_policy_model_json['unit'] = 'day'

        # Construct a model instance of CommonRotationPolicy by calling from_dict on the json representation
        common_rotation_policy_model = CommonRotationPolicy.from_dict(common_rotation_policy_model_json)
        assert common_rotation_policy_model != False

        # Construct a model instance of CommonRotationPolicy by calling from_dict on the json representation
        common_rotation_policy_model_dict = CommonRotationPolicy.from_dict(common_rotation_policy_model_json).__dict__
        common_rotation_policy_model2 = CommonRotationPolicy(**common_rotation_policy_model_dict)

        # Verify the model instances are equivalent
        assert common_rotation_policy_model == common_rotation_policy_model2

        # Convert model instance back to dict and verify no loss of data
        common_rotation_policy_model_json2 = common_rotation_policy_model.to_dict()
        assert common_rotation_policy_model_json2 == common_rotation_policy_model_json


class TestModel_IAMCredentialsConfiguration:
    """
    Test Class for IAMCredentialsConfiguration
    """

    def test_iam_credentials_configuration_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsConfiguration
        """

        # Construct a json representation of a IAMCredentialsConfiguration model
        iam_credentials_configuration_model_json = {}
        iam_credentials_configuration_model_json['config_type'] = 'iam_credentials_configuration'
        iam_credentials_configuration_model_json['name'] = 'my-secret-engine-config'
        iam_credentials_configuration_model_json['secret_type'] = 'arbitrary'
        iam_credentials_configuration_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_configuration_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_configuration_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_configuration_model_json['disabled'] = True

        # Construct a model instance of IAMCredentialsConfiguration by calling from_dict on the json representation
        iam_credentials_configuration_model = IAMCredentialsConfiguration.from_dict(
            iam_credentials_configuration_model_json)
        assert iam_credentials_configuration_model != False

        # Construct a model instance of IAMCredentialsConfiguration by calling from_dict on the json representation
        iam_credentials_configuration_model_dict = IAMCredentialsConfiguration.from_dict(
            iam_credentials_configuration_model_json).__dict__
        iam_credentials_configuration_model2 = IAMCredentialsConfiguration(**iam_credentials_configuration_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_configuration_model == iam_credentials_configuration_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_configuration_model_json2 = iam_credentials_configuration_model.to_dict()
        assert iam_credentials_configuration_model_json2 == iam_credentials_configuration_model_json


class TestModel_IAMCredentialsConfigurationMetadata:
    """
    Test Class for IAMCredentialsConfigurationMetadata
    """

    def test_iam_credentials_configuration_metadata_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsConfigurationMetadata
        """

        # Construct a json representation of a IAMCredentialsConfigurationMetadata model
        iam_credentials_configuration_metadata_model_json = {}
        iam_credentials_configuration_metadata_model_json['config_type'] = 'iam_credentials_configuration'
        iam_credentials_configuration_metadata_model_json['name'] = 'my-secret-engine-config'
        iam_credentials_configuration_metadata_model_json['secret_type'] = 'arbitrary'
        iam_credentials_configuration_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_configuration_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_configuration_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_configuration_metadata_model_json['disabled'] = True

        # Construct a model instance of IAMCredentialsConfigurationMetadata by calling from_dict on the json representation
        iam_credentials_configuration_metadata_model = IAMCredentialsConfigurationMetadata.from_dict(
            iam_credentials_configuration_metadata_model_json)
        assert iam_credentials_configuration_metadata_model != False

        # Construct a model instance of IAMCredentialsConfigurationMetadata by calling from_dict on the json representation
        iam_credentials_configuration_metadata_model_dict = IAMCredentialsConfigurationMetadata.from_dict(
            iam_credentials_configuration_metadata_model_json).__dict__
        iam_credentials_configuration_metadata_model2 = IAMCredentialsConfigurationMetadata(
            **iam_credentials_configuration_metadata_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_configuration_metadata_model == iam_credentials_configuration_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_configuration_metadata_model_json2 = iam_credentials_configuration_metadata_model.to_dict()
        assert iam_credentials_configuration_metadata_model_json2 == iam_credentials_configuration_metadata_model_json


class TestModel_IAMCredentialsConfigurationPatch:
    """
    Test Class for IAMCredentialsConfigurationPatch
    """

    def test_iam_credentials_configuration_patch_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsConfigurationPatch
        """

        # Construct a json representation of a IAMCredentialsConfigurationPatch model
        iam_credentials_configuration_patch_model_json = {}
        iam_credentials_configuration_patch_model_json['api_key'] = 'testString'
        iam_credentials_configuration_patch_model_json['disabled'] = True

        # Construct a model instance of IAMCredentialsConfigurationPatch by calling from_dict on the json representation
        iam_credentials_configuration_patch_model = IAMCredentialsConfigurationPatch.from_dict(
            iam_credentials_configuration_patch_model_json)
        assert iam_credentials_configuration_patch_model != False

        # Construct a model instance of IAMCredentialsConfigurationPatch by calling from_dict on the json representation
        iam_credentials_configuration_patch_model_dict = IAMCredentialsConfigurationPatch.from_dict(
            iam_credentials_configuration_patch_model_json).__dict__
        iam_credentials_configuration_patch_model2 = IAMCredentialsConfigurationPatch(
            **iam_credentials_configuration_patch_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_configuration_patch_model == iam_credentials_configuration_patch_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_configuration_patch_model_json2 = iam_credentials_configuration_patch_model.to_dict()
        assert iam_credentials_configuration_patch_model_json2 == iam_credentials_configuration_patch_model_json


class TestModel_IAMCredentialsConfigurationPrototype:
    """
    Test Class for IAMCredentialsConfigurationPrototype
    """

    def test_iam_credentials_configuration_prototype_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsConfigurationPrototype
        """

        # Construct a json representation of a IAMCredentialsConfigurationPrototype model
        iam_credentials_configuration_prototype_model_json = {}
        iam_credentials_configuration_prototype_model_json['name'] = 'my-example-engine-config'
        iam_credentials_configuration_prototype_model_json['config_type'] = 'iam_credentials_configuration'
        iam_credentials_configuration_prototype_model_json['api_key'] = 'testString'
        iam_credentials_configuration_prototype_model_json['disabled'] = False

        # Construct a model instance of IAMCredentialsConfigurationPrototype by calling from_dict on the json representation
        iam_credentials_configuration_prototype_model = IAMCredentialsConfigurationPrototype.from_dict(
            iam_credentials_configuration_prototype_model_json)
        assert iam_credentials_configuration_prototype_model != False

        # Construct a model instance of IAMCredentialsConfigurationPrototype by calling from_dict on the json representation
        iam_credentials_configuration_prototype_model_dict = IAMCredentialsConfigurationPrototype.from_dict(
            iam_credentials_configuration_prototype_model_json).__dict__
        iam_credentials_configuration_prototype_model2 = IAMCredentialsConfigurationPrototype(
            **iam_credentials_configuration_prototype_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_configuration_prototype_model == iam_credentials_configuration_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_configuration_prototype_model_json2 = iam_credentials_configuration_prototype_model.to_dict()
        assert iam_credentials_configuration_prototype_model_json2 == iam_credentials_configuration_prototype_model_json


class TestModel_IAMCredentialsSecret:
    """
    Test Class for IAMCredentialsSecret
    """

    def test_iam_credentials_secret_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a IAMCredentialsSecret model
        iam_credentials_secret_model_json = {}
        iam_credentials_secret_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_secret_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_model_json['crn'] = 'testString'
        iam_credentials_secret_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_model_json['description'] = 'Extended description for this secret.'
        iam_credentials_secret_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_model_json['labels'] = ['my-label']
        iam_credentials_secret_model_json['secret_group_id'] = 'default'
        iam_credentials_secret_model_json['secret_type'] = 'iam_credentials'
        iam_credentials_secret_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_model_json['versions_total'] = 0
        iam_credentials_secret_model_json['ttl'] = '1d'
        iam_credentials_secret_model_json['access_groups'] = ['AccessGroupId-45884031-54be-4dd7-86ff-112511e92699']
        iam_credentials_secret_model_json['service_id'] = 'ServiceId-bb4ccc31-bd31-493a-bb58-52ec399800be'
        iam_credentials_secret_model_json['account_id'] = '708d4dc20986423e79bb8512f81b7f92'
        iam_credentials_secret_model_json['reuse_api_key'] = True
        iam_credentials_secret_model_json['rotation'] = rotation_policy_model
        iam_credentials_secret_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of IAMCredentialsSecret by calling from_dict on the json representation
        iam_credentials_secret_model = IAMCredentialsSecret.from_dict(iam_credentials_secret_model_json)
        assert iam_credentials_secret_model != False

        # Construct a model instance of IAMCredentialsSecret by calling from_dict on the json representation
        iam_credentials_secret_model_dict = IAMCredentialsSecret.from_dict(iam_credentials_secret_model_json).__dict__
        iam_credentials_secret_model2 = IAMCredentialsSecret(**iam_credentials_secret_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_model == iam_credentials_secret_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_model_json2 = iam_credentials_secret_model.to_dict()
        assert iam_credentials_secret_model_json2 == iam_credentials_secret_model_json


class TestModel_IAMCredentialsSecretMetadata:
    """
    Test Class for IAMCredentialsSecretMetadata
    """

    def test_iam_credentials_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a IAMCredentialsSecretMetadata model
        iam_credentials_secret_metadata_model_json = {}
        iam_credentials_secret_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_secret_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_metadata_model_json['crn'] = 'testString'
        iam_credentials_secret_metadata_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        iam_credentials_secret_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_metadata_model_json['labels'] = ['my-label']
        iam_credentials_secret_metadata_model_json['secret_group_id'] = 'default'
        iam_credentials_secret_metadata_model_json['secret_type'] = 'iam_credentials'
        iam_credentials_secret_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_metadata_model_json['versions_total'] = 0
        iam_credentials_secret_metadata_model_json['ttl'] = '1d'
        iam_credentials_secret_metadata_model_json['access_groups'] = [
            'AccessGroupId-45884031-54be-4dd7-86ff-112511e92699']
        iam_credentials_secret_metadata_model_json['service_id'] = 'ServiceId-bb4ccc31-bd31-493a-bb58-52ec399800be'
        iam_credentials_secret_metadata_model_json['account_id'] = '708d4dc20986423e79bb8512f81b7f92'
        iam_credentials_secret_metadata_model_json['reuse_api_key'] = True
        iam_credentials_secret_metadata_model_json['rotation'] = rotation_policy_model
        iam_credentials_secret_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of IAMCredentialsSecretMetadata by calling from_dict on the json representation
        iam_credentials_secret_metadata_model = IAMCredentialsSecretMetadata.from_dict(
            iam_credentials_secret_metadata_model_json)
        assert iam_credentials_secret_metadata_model != False

        # Construct a model instance of IAMCredentialsSecretMetadata by calling from_dict on the json representation
        iam_credentials_secret_metadata_model_dict = IAMCredentialsSecretMetadata.from_dict(
            iam_credentials_secret_metadata_model_json).__dict__
        iam_credentials_secret_metadata_model2 = IAMCredentialsSecretMetadata(
            **iam_credentials_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_metadata_model == iam_credentials_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_metadata_model_json2 = iam_credentials_secret_metadata_model.to_dict()
        assert iam_credentials_secret_metadata_model_json2 == iam_credentials_secret_metadata_model_json


class TestModel_IAMCredentialsSecretMetadataPatch:
    """
    Test Class for IAMCredentialsSecretMetadataPatch
    """

    def test_iam_credentials_secret_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a IAMCredentialsSecretMetadataPatch model
        iam_credentials_secret_metadata_patch_model_json = {}
        iam_credentials_secret_metadata_patch_model_json['name'] = 'my-secret-example'
        iam_credentials_secret_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        iam_credentials_secret_metadata_patch_model_json['labels'] = ['my-label']
        iam_credentials_secret_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_metadata_patch_model_json['ttl'] = '1d'
        iam_credentials_secret_metadata_patch_model_json['rotation'] = rotation_policy_model

        # Construct a model instance of IAMCredentialsSecretMetadataPatch by calling from_dict on the json representation
        iam_credentials_secret_metadata_patch_model = IAMCredentialsSecretMetadataPatch.from_dict(
            iam_credentials_secret_metadata_patch_model_json)
        assert iam_credentials_secret_metadata_patch_model != False

        # Construct a model instance of IAMCredentialsSecretMetadataPatch by calling from_dict on the json representation
        iam_credentials_secret_metadata_patch_model_dict = IAMCredentialsSecretMetadataPatch.from_dict(
            iam_credentials_secret_metadata_patch_model_json).__dict__
        iam_credentials_secret_metadata_patch_model2 = IAMCredentialsSecretMetadataPatch(
            **iam_credentials_secret_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_metadata_patch_model == iam_credentials_secret_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_metadata_patch_model_json2 = iam_credentials_secret_metadata_patch_model.to_dict()
        assert iam_credentials_secret_metadata_patch_model_json2 == iam_credentials_secret_metadata_patch_model_json


class TestModel_IAMCredentialsSecretPrototype:
    """
    Test Class for IAMCredentialsSecretPrototype
    """

    def test_iam_credentials_secret_prototype_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a IAMCredentialsSecretPrototype model
        iam_credentials_secret_prototype_model_json = {}
        iam_credentials_secret_prototype_model_json['secret_type'] = 'iam_credentials'
        iam_credentials_secret_prototype_model_json['name'] = 'my-secret-example'
        iam_credentials_secret_prototype_model_json['description'] = 'Extended description for this secret.'
        iam_credentials_secret_prototype_model_json['secret_group_id'] = 'default'
        iam_credentials_secret_prototype_model_json['labels'] = ['my-label']
        iam_credentials_secret_prototype_model_json['ttl'] = '1d'
        iam_credentials_secret_prototype_model_json['access_groups'] = [
            'AccessGroupId-45884031-54be-4dd7-86ff-112511e92699']
        iam_credentials_secret_prototype_model_json['service_id'] = 'ServiceId-bb4ccc31-bd31-493a-bb58-52ec399800be'
        iam_credentials_secret_prototype_model_json['account_id'] = '708d4dc20986423e79bb8512f81b7f92'
        iam_credentials_secret_prototype_model_json['reuse_api_key'] = True
        iam_credentials_secret_prototype_model_json['rotation'] = rotation_policy_model
        iam_credentials_secret_prototype_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of IAMCredentialsSecretPrototype by calling from_dict on the json representation
        iam_credentials_secret_prototype_model = IAMCredentialsSecretPrototype.from_dict(
            iam_credentials_secret_prototype_model_json)
        assert iam_credentials_secret_prototype_model != False

        # Construct a model instance of IAMCredentialsSecretPrototype by calling from_dict on the json representation
        iam_credentials_secret_prototype_model_dict = IAMCredentialsSecretPrototype.from_dict(
            iam_credentials_secret_prototype_model_json).__dict__
        iam_credentials_secret_prototype_model2 = IAMCredentialsSecretPrototype(
            **iam_credentials_secret_prototype_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_prototype_model == iam_credentials_secret_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_prototype_model_json2 = iam_credentials_secret_prototype_model.to_dict()
        assert iam_credentials_secret_prototype_model_json2 == iam_credentials_secret_prototype_model_json


class TestModel_IAMCredentialsSecretRestoreFromVersionPrototype:
    """
    Test Class for IAMCredentialsSecretRestoreFromVersionPrototype
    """

    def test_iam_credentials_secret_restore_from_version_prototype_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretRestoreFromVersionPrototype
        """

        # Construct a json representation of a IAMCredentialsSecretRestoreFromVersionPrototype model
        iam_credentials_secret_restore_from_version_prototype_model_json = {}
        iam_credentials_secret_restore_from_version_prototype_model_json['restore_from_version'] = 'current'
        iam_credentials_secret_restore_from_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_restore_from_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of IAMCredentialsSecretRestoreFromVersionPrototype by calling from_dict on the json representation
        iam_credentials_secret_restore_from_version_prototype_model = IAMCredentialsSecretRestoreFromVersionPrototype.from_dict(
            iam_credentials_secret_restore_from_version_prototype_model_json)
        assert iam_credentials_secret_restore_from_version_prototype_model != False

        # Construct a model instance of IAMCredentialsSecretRestoreFromVersionPrototype by calling from_dict on the json representation
        iam_credentials_secret_restore_from_version_prototype_model_dict = IAMCredentialsSecretRestoreFromVersionPrototype.from_dict(
            iam_credentials_secret_restore_from_version_prototype_model_json).__dict__
        iam_credentials_secret_restore_from_version_prototype_model2 = IAMCredentialsSecretRestoreFromVersionPrototype(
            **iam_credentials_secret_restore_from_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_restore_from_version_prototype_model == iam_credentials_secret_restore_from_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_restore_from_version_prototype_model_json2 = iam_credentials_secret_restore_from_version_prototype_model.to_dict()
        assert iam_credentials_secret_restore_from_version_prototype_model_json2 == iam_credentials_secret_restore_from_version_prototype_model_json


class TestModel_IAMCredentialsSecretVersion:
    """
    Test Class for IAMCredentialsSecretVersion
    """

    def test_iam_credentials_secret_version_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretVersion
        """

        # Construct a json representation of a IAMCredentialsSecretVersion model
        iam_credentials_secret_version_model_json = {}
        iam_credentials_secret_version_model_json['auto_rotated'] = True
        iam_credentials_secret_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_secret_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_version_model_json['secret_type'] = 'iam_credentials'
        iam_credentials_secret_version_model_json['secret_group_id'] = 'default'
        iam_credentials_secret_version_model_json['payload_available'] = True
        iam_credentials_secret_version_model_json['alias'] = 'current'
        iam_credentials_secret_version_model_json['version_custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        iam_credentials_secret_version_model_json['service_id'] = 'ServiceId-bb4ccc31-bd31-493a-bb58-52ec399800be'

        # Construct a model instance of IAMCredentialsSecretVersion by calling from_dict on the json representation
        iam_credentials_secret_version_model = IAMCredentialsSecretVersion.from_dict(
            iam_credentials_secret_version_model_json)
        assert iam_credentials_secret_version_model != False

        # Construct a model instance of IAMCredentialsSecretVersion by calling from_dict on the json representation
        iam_credentials_secret_version_model_dict = IAMCredentialsSecretVersion.from_dict(
            iam_credentials_secret_version_model_json).__dict__
        iam_credentials_secret_version_model2 = IAMCredentialsSecretVersion(**iam_credentials_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_version_model == iam_credentials_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_version_model_json2 = iam_credentials_secret_version_model.to_dict()
        assert iam_credentials_secret_version_model_json2 == iam_credentials_secret_version_model_json


class TestModel_IAMCredentialsSecretVersionMetadata:
    """
    Test Class for IAMCredentialsSecretVersionMetadata
    """

    def test_iam_credentials_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretVersionMetadata
        """

        # Construct a json representation of a IAMCredentialsSecretVersionMetadata model
        iam_credentials_secret_version_metadata_model_json = {}
        iam_credentials_secret_version_metadata_model_json['auto_rotated'] = True
        iam_credentials_secret_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        iam_credentials_secret_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        iam_credentials_secret_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_version_metadata_model_json['secret_type'] = 'iam_credentials'
        iam_credentials_secret_version_metadata_model_json['secret_group_id'] = 'default'
        iam_credentials_secret_version_metadata_model_json['payload_available'] = True
        iam_credentials_secret_version_metadata_model_json['alias'] = 'current'
        iam_credentials_secret_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        iam_credentials_secret_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        iam_credentials_secret_version_metadata_model_json[
            'service_id'] = 'ServiceId-bb4ccc31-bd31-493a-bb58-52ec399800be'

        # Construct a model instance of IAMCredentialsSecretVersionMetadata by calling from_dict on the json representation
        iam_credentials_secret_version_metadata_model = IAMCredentialsSecretVersionMetadata.from_dict(
            iam_credentials_secret_version_metadata_model_json)
        assert iam_credentials_secret_version_metadata_model != False

        # Construct a model instance of IAMCredentialsSecretVersionMetadata by calling from_dict on the json representation
        iam_credentials_secret_version_metadata_model_dict = IAMCredentialsSecretVersionMetadata.from_dict(
            iam_credentials_secret_version_metadata_model_json).__dict__
        iam_credentials_secret_version_metadata_model2 = IAMCredentialsSecretVersionMetadata(
            **iam_credentials_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_version_metadata_model == iam_credentials_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_version_metadata_model_json2 = iam_credentials_secret_version_metadata_model.to_dict()
        assert iam_credentials_secret_version_metadata_model_json2 == iam_credentials_secret_version_metadata_model_json


class TestModel_IAMCredentialsSecretVersionPrototype:
    """
    Test Class for IAMCredentialsSecretVersionPrototype
    """

    def test_iam_credentials_secret_version_prototype_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretVersionPrototype
        """

        # Construct a json representation of a IAMCredentialsSecretVersionPrototype model
        iam_credentials_secret_version_prototype_model_json = {}
        iam_credentials_secret_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        iam_credentials_secret_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of IAMCredentialsSecretVersionPrototype by calling from_dict on the json representation
        iam_credentials_secret_version_prototype_model = IAMCredentialsSecretVersionPrototype.from_dict(
            iam_credentials_secret_version_prototype_model_json)
        assert iam_credentials_secret_version_prototype_model != False

        # Construct a model instance of IAMCredentialsSecretVersionPrototype by calling from_dict on the json representation
        iam_credentials_secret_version_prototype_model_dict = IAMCredentialsSecretVersionPrototype.from_dict(
            iam_credentials_secret_version_prototype_model_json).__dict__
        iam_credentials_secret_version_prototype_model2 = IAMCredentialsSecretVersionPrototype(
            **iam_credentials_secret_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_version_prototype_model == iam_credentials_secret_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_version_prototype_model_json2 = iam_credentials_secret_version_prototype_model.to_dict()
        assert iam_credentials_secret_version_prototype_model_json2 == iam_credentials_secret_version_prototype_model_json


class TestModel_ImportedCertificate:
    """
    Test Class for ImportedCertificate
    """

    def test_imported_certificate_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificate
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        imported_certificate_managed_csr_response_model = {}  # ImportedCertificateManagedCsrResponse
        imported_certificate_managed_csr_response_model['ou'] = ['testString']
        imported_certificate_managed_csr_response_model['organization'] = ['testString']
        imported_certificate_managed_csr_response_model['country'] = ['testString']
        imported_certificate_managed_csr_response_model['locality'] = ['testString']
        imported_certificate_managed_csr_response_model['province'] = ['testString']
        imported_certificate_managed_csr_response_model['street_address'] = ['testString']
        imported_certificate_managed_csr_response_model['postal_code'] = ['testString']
        imported_certificate_managed_csr_response_model['require_cn'] = True
        imported_certificate_managed_csr_response_model['common_name'] = 'example.com'
        imported_certificate_managed_csr_response_model['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_response_model['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_response_model['uri_sans'] = 'testString'
        imported_certificate_managed_csr_response_model['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_response_model['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_response_model['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_response_model['server_flag'] = True
        imported_certificate_managed_csr_response_model['client_flag'] = True
        imported_certificate_managed_csr_response_model['code_signing_flag'] = True
        imported_certificate_managed_csr_response_model['email_protection_flag'] = True
        imported_certificate_managed_csr_response_model['key_type'] = 'rsa'
        imported_certificate_managed_csr_response_model['key_bits'] = 4096
        imported_certificate_managed_csr_response_model['key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_response_model['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_response_model['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_response_model['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_response_model['rotate_keys'] = True
        imported_certificate_managed_csr_response_model['csr'] = 'testString'
        imported_certificate_managed_csr_response_model['private_key'] = 'testString'

        # Construct a json representation of a ImportedCertificate model
        imported_certificate_model_json = {}
        imported_certificate_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        imported_certificate_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_model_json['crn'] = 'testString'
        imported_certificate_model_json['custom_metadata'] = {'key': 'value'}
        imported_certificate_model_json['description'] = 'Extended description for this secret.'
        imported_certificate_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_model_json['labels'] = ['my-label']
        imported_certificate_model_json['secret_group_id'] = 'default'
        imported_certificate_model_json['secret_type'] = 'imported_cert'
        imported_certificate_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_model_json['versions_total'] = 0
        imported_certificate_model_json['signing_algorithm'] = 'SHA256-RSA'
        imported_certificate_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        imported_certificate_model_json['common_name'] = 'example.com'
        imported_certificate_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        imported_certificate_model_json['intermediate_included'] = True
        imported_certificate_model_json['issuer'] = 'Lets Encrypt'
        imported_certificate_model_json['private_key_included'] = True
        imported_certificate_model_json['serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        imported_certificate_model_json['validity'] = certificate_validity_model
        imported_certificate_model_json['managed_csr'] = imported_certificate_managed_csr_response_model
        imported_certificate_model_json['certificate'] = 'testString'
        imported_certificate_model_json['intermediate'] = 'testString'
        imported_certificate_model_json['private_key'] = 'testString'
        imported_certificate_model_json['csr'] = 'testString'

        # Construct a model instance of ImportedCertificate by calling from_dict on the json representation
        imported_certificate_model = ImportedCertificate.from_dict(imported_certificate_model_json)
        assert imported_certificate_model != False

        # Construct a model instance of ImportedCertificate by calling from_dict on the json representation
        imported_certificate_model_dict = ImportedCertificate.from_dict(imported_certificate_model_json).__dict__
        imported_certificate_model2 = ImportedCertificate(**imported_certificate_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_model == imported_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_model_json2 = imported_certificate_model.to_dict()
        assert imported_certificate_model_json2 == imported_certificate_model_json


class TestModel_ImportedCertificateMetadata:
    """
    Test Class for ImportedCertificateMetadata
    """

    def test_imported_certificate_metadata_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        imported_certificate_managed_csr_response_model = {}  # ImportedCertificateManagedCsrResponse
        imported_certificate_managed_csr_response_model['ou'] = ['testString']
        imported_certificate_managed_csr_response_model['organization'] = ['testString']
        imported_certificate_managed_csr_response_model['country'] = ['testString']
        imported_certificate_managed_csr_response_model['locality'] = ['testString']
        imported_certificate_managed_csr_response_model['province'] = ['testString']
        imported_certificate_managed_csr_response_model['street_address'] = ['testString']
        imported_certificate_managed_csr_response_model['postal_code'] = ['testString']
        imported_certificate_managed_csr_response_model['require_cn'] = True
        imported_certificate_managed_csr_response_model['common_name'] = 'example.com'
        imported_certificate_managed_csr_response_model['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_response_model['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_response_model['uri_sans'] = 'testString'
        imported_certificate_managed_csr_response_model['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_response_model['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_response_model['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_response_model['server_flag'] = True
        imported_certificate_managed_csr_response_model['client_flag'] = True
        imported_certificate_managed_csr_response_model['code_signing_flag'] = True
        imported_certificate_managed_csr_response_model['email_protection_flag'] = True
        imported_certificate_managed_csr_response_model['key_type'] = 'rsa'
        imported_certificate_managed_csr_response_model['key_bits'] = 4096
        imported_certificate_managed_csr_response_model['key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_response_model['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_response_model['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_response_model['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_response_model['rotate_keys'] = True
        imported_certificate_managed_csr_response_model['csr'] = 'testString'
        imported_certificate_managed_csr_response_model['private_key'] = 'testString'

        # Construct a json representation of a ImportedCertificateMetadata model
        imported_certificate_metadata_model_json = {}
        imported_certificate_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        imported_certificate_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_metadata_model_json['crn'] = 'testString'
        imported_certificate_metadata_model_json['custom_metadata'] = {'key': 'value'}
        imported_certificate_metadata_model_json['description'] = 'Extended description for this secret.'
        imported_certificate_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_metadata_model_json['labels'] = ['my-label']
        imported_certificate_metadata_model_json['secret_group_id'] = 'default'
        imported_certificate_metadata_model_json['secret_type'] = 'imported_cert'
        imported_certificate_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_metadata_model_json['versions_total'] = 0
        imported_certificate_metadata_model_json['signing_algorithm'] = 'SHA256-RSA'
        imported_certificate_metadata_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        imported_certificate_metadata_model_json['common_name'] = 'example.com'
        imported_certificate_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        imported_certificate_metadata_model_json['intermediate_included'] = True
        imported_certificate_metadata_model_json['issuer'] = 'Lets Encrypt'
        imported_certificate_metadata_model_json['private_key_included'] = True
        imported_certificate_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        imported_certificate_metadata_model_json['validity'] = certificate_validity_model
        imported_certificate_metadata_model_json['managed_csr'] = imported_certificate_managed_csr_response_model

        # Construct a model instance of ImportedCertificateMetadata by calling from_dict on the json representation
        imported_certificate_metadata_model = ImportedCertificateMetadata.from_dict(
            imported_certificate_metadata_model_json)
        assert imported_certificate_metadata_model != False

        # Construct a model instance of ImportedCertificateMetadata by calling from_dict on the json representation
        imported_certificate_metadata_model_dict = ImportedCertificateMetadata.from_dict(
            imported_certificate_metadata_model_json).__dict__
        imported_certificate_metadata_model2 = ImportedCertificateMetadata(**imported_certificate_metadata_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_metadata_model == imported_certificate_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_metadata_model_json2 = imported_certificate_metadata_model.to_dict()
        assert imported_certificate_metadata_model_json2 == imported_certificate_metadata_model_json


class TestModel_ImportedCertificateMetadataPatch:
    """
    Test Class for ImportedCertificateMetadataPatch
    """

    def test_imported_certificate_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        imported_certificate_managed_csr_model = {}  # ImportedCertificateManagedCsr
        imported_certificate_managed_csr_model['ou'] = ['testString']
        imported_certificate_managed_csr_model['organization'] = ['testString']
        imported_certificate_managed_csr_model['country'] = ['testString']
        imported_certificate_managed_csr_model['locality'] = ['testString']
        imported_certificate_managed_csr_model['province'] = ['testString']
        imported_certificate_managed_csr_model['street_address'] = ['testString']
        imported_certificate_managed_csr_model['postal_code'] = ['testString']
        imported_certificate_managed_csr_model['require_cn'] = True
        imported_certificate_managed_csr_model['common_name'] = 'example.com'
        imported_certificate_managed_csr_model['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_model['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_model['uri_sans'] = 'testString'
        imported_certificate_managed_csr_model['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_model['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_model['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_model['server_flag'] = True
        imported_certificate_managed_csr_model['client_flag'] = True
        imported_certificate_managed_csr_model['code_signing_flag'] = True
        imported_certificate_managed_csr_model['email_protection_flag'] = True
        imported_certificate_managed_csr_model['key_type'] = 'rsa'
        imported_certificate_managed_csr_model['key_bits'] = 4096
        imported_certificate_managed_csr_model['key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_model['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_model['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_model['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_model['rotate_keys'] = True

        # Construct a json representation of a ImportedCertificateMetadataPatch model
        imported_certificate_metadata_patch_model_json = {}
        imported_certificate_metadata_patch_model_json['name'] = 'my-secret-example'
        imported_certificate_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        imported_certificate_metadata_patch_model_json['labels'] = ['my-label']
        imported_certificate_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        imported_certificate_metadata_patch_model_json['managed_csr'] = imported_certificate_managed_csr_model

        # Construct a model instance of ImportedCertificateMetadataPatch by calling from_dict on the json representation
        imported_certificate_metadata_patch_model = ImportedCertificateMetadataPatch.from_dict(
            imported_certificate_metadata_patch_model_json)
        assert imported_certificate_metadata_patch_model != False

        # Construct a model instance of ImportedCertificateMetadataPatch by calling from_dict on the json representation
        imported_certificate_metadata_patch_model_dict = ImportedCertificateMetadataPatch.from_dict(
            imported_certificate_metadata_patch_model_json).__dict__
        imported_certificate_metadata_patch_model2 = ImportedCertificateMetadataPatch(
            **imported_certificate_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_metadata_patch_model == imported_certificate_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_metadata_patch_model_json2 = imported_certificate_metadata_patch_model.to_dict()
        assert imported_certificate_metadata_patch_model_json2 == imported_certificate_metadata_patch_model_json


class TestModel_ImportedCertificatePrototype:
    """
    Test Class for ImportedCertificatePrototype
    """

    def test_imported_certificate_prototype_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificatePrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        imported_certificate_managed_csr_model = {}  # ImportedCertificateManagedCsr
        imported_certificate_managed_csr_model['ou'] = ['testString']
        imported_certificate_managed_csr_model['organization'] = ['testString']
        imported_certificate_managed_csr_model['country'] = ['testString']
        imported_certificate_managed_csr_model['locality'] = ['testString']
        imported_certificate_managed_csr_model['province'] = ['testString']
        imported_certificate_managed_csr_model['street_address'] = ['testString']
        imported_certificate_managed_csr_model['postal_code'] = ['testString']
        imported_certificate_managed_csr_model['require_cn'] = True
        imported_certificate_managed_csr_model['common_name'] = 'example.com'
        imported_certificate_managed_csr_model['alt_names'] = 'alt-name-1,alt-name-2'
        imported_certificate_managed_csr_model['ip_sans'] = '1.1.1.1,2.2.2.2'
        imported_certificate_managed_csr_model['uri_sans'] = 'testString'
        imported_certificate_managed_csr_model['other_sans'] = '2.5.4.5;UTF8:*.example.com'
        imported_certificate_managed_csr_model['exclude_cn_from_sans'] = True
        imported_certificate_managed_csr_model['user_ids'] = 'user-1,user-2'
        imported_certificate_managed_csr_model['server_flag'] = True
        imported_certificate_managed_csr_model['client_flag'] = True
        imported_certificate_managed_csr_model['code_signing_flag'] = True
        imported_certificate_managed_csr_model['email_protection_flag'] = True
        imported_certificate_managed_csr_model['key_type'] = 'rsa'
        imported_certificate_managed_csr_model['key_bits'] = 4096
        imported_certificate_managed_csr_model['key_usage'] = 'DigitalSignature,KeyAgreement,KeyEncipherment'
        imported_certificate_managed_csr_model['ext_key_usage'] = 'ServerAuth,ClientAuth,EmailProtection'
        imported_certificate_managed_csr_model['policy_identifiers'] = 'testString'
        imported_certificate_managed_csr_model['ext_key_usage_oids'] = 'testString'
        imported_certificate_managed_csr_model['rotate_keys'] = True

        # Construct a json representation of a ImportedCertificatePrototype model
        imported_certificate_prototype_model_json = {}
        imported_certificate_prototype_model_json['secret_type'] = 'imported_cert'
        imported_certificate_prototype_model_json['name'] = 'my-secret-example'
        imported_certificate_prototype_model_json['description'] = 'Extended description for this secret.'
        imported_certificate_prototype_model_json['secret_group_id'] = 'default'
        imported_certificate_prototype_model_json['labels'] = ['my-label']
        imported_certificate_prototype_model_json['certificate'] = 'testString'
        imported_certificate_prototype_model_json['intermediate'] = 'testString'
        imported_certificate_prototype_model_json['private_key'] = 'testString'
        imported_certificate_prototype_model_json['managed_csr'] = imported_certificate_managed_csr_model
        imported_certificate_prototype_model_json['custom_metadata'] = {'key': 'value'}
        imported_certificate_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ImportedCertificatePrototype by calling from_dict on the json representation
        imported_certificate_prototype_model = ImportedCertificatePrototype.from_dict(
            imported_certificate_prototype_model_json)
        assert imported_certificate_prototype_model != False

        # Construct a model instance of ImportedCertificatePrototype by calling from_dict on the json representation
        imported_certificate_prototype_model_dict = ImportedCertificatePrototype.from_dict(
            imported_certificate_prototype_model_json).__dict__
        imported_certificate_prototype_model2 = ImportedCertificatePrototype(
            **imported_certificate_prototype_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_prototype_model == imported_certificate_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_prototype_model_json2 = imported_certificate_prototype_model.to_dict()
        assert imported_certificate_prototype_model_json2 == imported_certificate_prototype_model_json


class TestModel_ImportedCertificateVersion:
    """
    Test Class for ImportedCertificateVersion
    """

    def test_imported_certificate_version_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a ImportedCertificateVersion model
        imported_certificate_version_model_json = {}
        imported_certificate_version_model_json['auto_rotated'] = True
        imported_certificate_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        imported_certificate_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_version_model_json['secret_type'] = 'imported_cert'
        imported_certificate_version_model_json['secret_group_id'] = 'default'
        imported_certificate_version_model_json['payload_available'] = True
        imported_certificate_version_model_json['alias'] = 'current'
        imported_certificate_version_model_json['version_custom_metadata'] = {'key': 'value'}
        imported_certificate_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        imported_certificate_version_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        imported_certificate_version_model_json['validity'] = certificate_validity_model
        imported_certificate_version_model_json['certificate'] = 'testString'
        imported_certificate_version_model_json['intermediate'] = 'testString'
        imported_certificate_version_model_json['private_key'] = 'testString'
        imported_certificate_version_model_json['csr'] = 'testString'

        # Construct a model instance of ImportedCertificateVersion by calling from_dict on the json representation
        imported_certificate_version_model = ImportedCertificateVersion.from_dict(
            imported_certificate_version_model_json)
        assert imported_certificate_version_model != False

        # Construct a model instance of ImportedCertificateVersion by calling from_dict on the json representation
        imported_certificate_version_model_dict = ImportedCertificateVersion.from_dict(
            imported_certificate_version_model_json).__dict__
        imported_certificate_version_model2 = ImportedCertificateVersion(**imported_certificate_version_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_version_model == imported_certificate_version_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_version_model_json2 = imported_certificate_version_model.to_dict()
        assert imported_certificate_version_model_json2 == imported_certificate_version_model_json


class TestModel_ImportedCertificateVersionMetadata:
    """
    Test Class for ImportedCertificateVersionMetadata
    """

    def test_imported_certificate_version_metadata_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a ImportedCertificateVersionMetadata model
        imported_certificate_version_metadata_model_json = {}
        imported_certificate_version_metadata_model_json['auto_rotated'] = True
        imported_certificate_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        imported_certificate_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        imported_certificate_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_version_metadata_model_json['secret_type'] = 'imported_cert'
        imported_certificate_version_metadata_model_json['secret_group_id'] = 'default'
        imported_certificate_version_metadata_model_json['payload_available'] = True
        imported_certificate_version_metadata_model_json['alias'] = 'current'
        imported_certificate_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        imported_certificate_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        imported_certificate_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        imported_certificate_version_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        imported_certificate_version_metadata_model_json['validity'] = certificate_validity_model

        # Construct a model instance of ImportedCertificateVersionMetadata by calling from_dict on the json representation
        imported_certificate_version_metadata_model = ImportedCertificateVersionMetadata.from_dict(
            imported_certificate_version_metadata_model_json)
        assert imported_certificate_version_metadata_model != False

        # Construct a model instance of ImportedCertificateVersionMetadata by calling from_dict on the json representation
        imported_certificate_version_metadata_model_dict = ImportedCertificateVersionMetadata.from_dict(
            imported_certificate_version_metadata_model_json).__dict__
        imported_certificate_version_metadata_model2 = ImportedCertificateVersionMetadata(
            **imported_certificate_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_version_metadata_model == imported_certificate_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_version_metadata_model_json2 = imported_certificate_version_metadata_model.to_dict()
        assert imported_certificate_version_metadata_model_json2 == imported_certificate_version_metadata_model_json


class TestModel_ImportedCertificateVersionPrototype:
    """
    Test Class for ImportedCertificateVersionPrototype
    """

    def test_imported_certificate_version_prototype_serialization(self):
        """
        Test serialization/deserialization for ImportedCertificateVersionPrototype
        """

        # Construct a json representation of a ImportedCertificateVersionPrototype model
        imported_certificate_version_prototype_model_json = {}
        imported_certificate_version_prototype_model_json['certificate'] = 'testString'
        imported_certificate_version_prototype_model_json['intermediate'] = 'testString'
        imported_certificate_version_prototype_model_json['private_key'] = 'testString'
        imported_certificate_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        imported_certificate_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ImportedCertificateVersionPrototype by calling from_dict on the json representation
        imported_certificate_version_prototype_model = ImportedCertificateVersionPrototype.from_dict(
            imported_certificate_version_prototype_model_json)
        assert imported_certificate_version_prototype_model != False

        # Construct a model instance of ImportedCertificateVersionPrototype by calling from_dict on the json representation
        imported_certificate_version_prototype_model_dict = ImportedCertificateVersionPrototype.from_dict(
            imported_certificate_version_prototype_model_json).__dict__
        imported_certificate_version_prototype_model2 = ImportedCertificateVersionPrototype(
            **imported_certificate_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert imported_certificate_version_prototype_model == imported_certificate_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        imported_certificate_version_prototype_model_json2 = imported_certificate_version_prototype_model.to_dict()
        assert imported_certificate_version_prototype_model_json2 == imported_certificate_version_prototype_model_json


class TestModel_KVSecret:
    """
    Test Class for KVSecret
    """

    def test_kv_secret_serialization(self):
        """
        Test serialization/deserialization for KVSecret
        """

        # Construct a json representation of a KVSecret model
        kv_secret_model_json = {}
        kv_secret_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        kv_secret_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_model_json['crn'] = 'testString'
        kv_secret_model_json['custom_metadata'] = {'key': 'value'}
        kv_secret_model_json['description'] = 'Extended description for this secret.'
        kv_secret_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_model_json['labels'] = ['my-label']
        kv_secret_model_json['secret_group_id'] = 'default'
        kv_secret_model_json['secret_type'] = 'kv'
        kv_secret_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_model_json['versions_total'] = 0
        kv_secret_model_json['data'] = {'key': 'value'}

        # Construct a model instance of KVSecret by calling from_dict on the json representation
        kv_secret_model = KVSecret.from_dict(kv_secret_model_json)
        assert kv_secret_model != False

        # Construct a model instance of KVSecret by calling from_dict on the json representation
        kv_secret_model_dict = KVSecret.from_dict(kv_secret_model_json).__dict__
        kv_secret_model2 = KVSecret(**kv_secret_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_model == kv_secret_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_model_json2 = kv_secret_model.to_dict()
        assert kv_secret_model_json2 == kv_secret_model_json


class TestModel_KVSecretMetadata:
    """
    Test Class for KVSecretMetadata
    """

    def test_kv_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for KVSecretMetadata
        """

        # Construct a json representation of a KVSecretMetadata model
        kv_secret_metadata_model_json = {}
        kv_secret_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        kv_secret_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_metadata_model_json['crn'] = 'testString'
        kv_secret_metadata_model_json['custom_metadata'] = {'key': 'value'}
        kv_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        kv_secret_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_metadata_model_json['labels'] = ['my-label']
        kv_secret_metadata_model_json['secret_group_id'] = 'default'
        kv_secret_metadata_model_json['secret_type'] = 'kv'
        kv_secret_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_metadata_model_json['versions_total'] = 0

        # Construct a model instance of KVSecretMetadata by calling from_dict on the json representation
        kv_secret_metadata_model = KVSecretMetadata.from_dict(kv_secret_metadata_model_json)
        assert kv_secret_metadata_model != False

        # Construct a model instance of KVSecretMetadata by calling from_dict on the json representation
        kv_secret_metadata_model_dict = KVSecretMetadata.from_dict(kv_secret_metadata_model_json).__dict__
        kv_secret_metadata_model2 = KVSecretMetadata(**kv_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_metadata_model == kv_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_metadata_model_json2 = kv_secret_metadata_model.to_dict()
        assert kv_secret_metadata_model_json2 == kv_secret_metadata_model_json


class TestModel_KVSecretMetadataPatch:
    """
    Test Class for KVSecretMetadataPatch
    """

    def test_kv_secret_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for KVSecretMetadataPatch
        """

        # Construct a json representation of a KVSecretMetadataPatch model
        kv_secret_metadata_patch_model_json = {}
        kv_secret_metadata_patch_model_json['name'] = 'my-secret-example'
        kv_secret_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        kv_secret_metadata_patch_model_json['labels'] = ['my-label']
        kv_secret_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}

        # Construct a model instance of KVSecretMetadataPatch by calling from_dict on the json representation
        kv_secret_metadata_patch_model = KVSecretMetadataPatch.from_dict(kv_secret_metadata_patch_model_json)
        assert kv_secret_metadata_patch_model != False

        # Construct a model instance of KVSecretMetadataPatch by calling from_dict on the json representation
        kv_secret_metadata_patch_model_dict = KVSecretMetadataPatch.from_dict(
            kv_secret_metadata_patch_model_json).__dict__
        kv_secret_metadata_patch_model2 = KVSecretMetadataPatch(**kv_secret_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_metadata_patch_model == kv_secret_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_metadata_patch_model_json2 = kv_secret_metadata_patch_model.to_dict()
        assert kv_secret_metadata_patch_model_json2 == kv_secret_metadata_patch_model_json


class TestModel_KVSecretPrototype:
    """
    Test Class for KVSecretPrototype
    """

    def test_kv_secret_prototype_serialization(self):
        """
        Test serialization/deserialization for KVSecretPrototype
        """

        # Construct a json representation of a KVSecretPrototype model
        kv_secret_prototype_model_json = {}
        kv_secret_prototype_model_json['secret_type'] = 'kv'
        kv_secret_prototype_model_json['name'] = 'my-secret-example'
        kv_secret_prototype_model_json['description'] = 'Extended description for this secret.'
        kv_secret_prototype_model_json['secret_group_id'] = 'default'
        kv_secret_prototype_model_json['labels'] = ['my-label']
        kv_secret_prototype_model_json['data'] = {'key': 'value'}
        kv_secret_prototype_model_json['custom_metadata'] = {'key': 'value'}
        kv_secret_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of KVSecretPrototype by calling from_dict on the json representation
        kv_secret_prototype_model = KVSecretPrototype.from_dict(kv_secret_prototype_model_json)
        assert kv_secret_prototype_model != False

        # Construct a model instance of KVSecretPrototype by calling from_dict on the json representation
        kv_secret_prototype_model_dict = KVSecretPrototype.from_dict(kv_secret_prototype_model_json).__dict__
        kv_secret_prototype_model2 = KVSecretPrototype(**kv_secret_prototype_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_prototype_model == kv_secret_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_prototype_model_json2 = kv_secret_prototype_model.to_dict()
        assert kv_secret_prototype_model_json2 == kv_secret_prototype_model_json


class TestModel_KVSecretVersion:
    """
    Test Class for KVSecretVersion
    """

    def test_kv_secret_version_serialization(self):
        """
        Test serialization/deserialization for KVSecretVersion
        """

        # Construct a json representation of a KVSecretVersion model
        kv_secret_version_model_json = {}
        kv_secret_version_model_json['auto_rotated'] = True
        kv_secret_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        kv_secret_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_version_model_json['secret_type'] = 'kv'
        kv_secret_version_model_json['secret_group_id'] = 'default'
        kv_secret_version_model_json['payload_available'] = True
        kv_secret_version_model_json['alias'] = 'current'
        kv_secret_version_model_json['version_custom_metadata'] = {'key': 'value'}
        kv_secret_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        kv_secret_version_model_json['data'] = {'key': 'value'}

        # Construct a model instance of KVSecretVersion by calling from_dict on the json representation
        kv_secret_version_model = KVSecretVersion.from_dict(kv_secret_version_model_json)
        assert kv_secret_version_model != False

        # Construct a model instance of KVSecretVersion by calling from_dict on the json representation
        kv_secret_version_model_dict = KVSecretVersion.from_dict(kv_secret_version_model_json).__dict__
        kv_secret_version_model2 = KVSecretVersion(**kv_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_version_model == kv_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_version_model_json2 = kv_secret_version_model.to_dict()
        assert kv_secret_version_model_json2 == kv_secret_version_model_json


class TestModel_KVSecretVersionMetadata:
    """
    Test Class for KVSecretVersionMetadata
    """

    def test_kv_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for KVSecretVersionMetadata
        """

        # Construct a json representation of a KVSecretVersionMetadata model
        kv_secret_version_metadata_model_json = {}
        kv_secret_version_metadata_model_json['auto_rotated'] = True
        kv_secret_version_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        kv_secret_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        kv_secret_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_version_metadata_model_json['secret_type'] = 'kv'
        kv_secret_version_metadata_model_json['secret_group_id'] = 'default'
        kv_secret_version_metadata_model_json['payload_available'] = True
        kv_secret_version_metadata_model_json['alias'] = 'current'
        kv_secret_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        kv_secret_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        kv_secret_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of KVSecretVersionMetadata by calling from_dict on the json representation
        kv_secret_version_metadata_model = KVSecretVersionMetadata.from_dict(kv_secret_version_metadata_model_json)
        assert kv_secret_version_metadata_model != False

        # Construct a model instance of KVSecretVersionMetadata by calling from_dict on the json representation
        kv_secret_version_metadata_model_dict = KVSecretVersionMetadata.from_dict(
            kv_secret_version_metadata_model_json).__dict__
        kv_secret_version_metadata_model2 = KVSecretVersionMetadata(**kv_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_version_metadata_model == kv_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_version_metadata_model_json2 = kv_secret_version_metadata_model.to_dict()
        assert kv_secret_version_metadata_model_json2 == kv_secret_version_metadata_model_json


class TestModel_KVSecretVersionPrototype:
    """
    Test Class for KVSecretVersionPrototype
    """

    def test_kv_secret_version_prototype_serialization(self):
        """
        Test serialization/deserialization for KVSecretVersionPrototype
        """

        # Construct a json representation of a KVSecretVersionPrototype model
        kv_secret_version_prototype_model_json = {}
        kv_secret_version_prototype_model_json['data'] = {'key': 'value'}
        kv_secret_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        kv_secret_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of KVSecretVersionPrototype by calling from_dict on the json representation
        kv_secret_version_prototype_model = KVSecretVersionPrototype.from_dict(kv_secret_version_prototype_model_json)
        assert kv_secret_version_prototype_model != False

        # Construct a model instance of KVSecretVersionPrototype by calling from_dict on the json representation
        kv_secret_version_prototype_model_dict = KVSecretVersionPrototype.from_dict(
            kv_secret_version_prototype_model_json).__dict__
        kv_secret_version_prototype_model2 = KVSecretVersionPrototype(**kv_secret_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert kv_secret_version_prototype_model == kv_secret_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        kv_secret_version_prototype_model_json2 = kv_secret_version_prototype_model.to_dict()
        assert kv_secret_version_prototype_model_json2 == kv_secret_version_prototype_model_json


class TestModel_PrivateCertificate:
    """
    Test Class for PrivateCertificate
    """

    def test_private_certificate_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificate
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PrivateCertificate model
        private_certificate_model_json = {}
        private_certificate_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_model_json['crn'] = 'testString'
        private_certificate_model_json['custom_metadata'] = {'key': 'value'}
        private_certificate_model_json['description'] = 'Extended description for this secret.'
        private_certificate_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_model_json['labels'] = ['my-label']
        private_certificate_model_json['secret_group_id'] = 'default'
        private_certificate_model_json['secret_type'] = 'private_cert'
        private_certificate_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_model_json['versions_total'] = 0
        private_certificate_model_json['signing_algorithm'] = 'SHA256-RSA'
        private_certificate_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_model_json['certificate_template'] = 'cert-template-1'
        private_certificate_model_json['common_name'] = 'localhost'
        private_certificate_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_model_json['issuer'] = 'Lets Encrypt'
        private_certificate_model_json['rotation'] = rotation_policy_model
        private_certificate_model_json['serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_model_json['validity'] = certificate_validity_model
        private_certificate_model_json['certificate'] = 'testString'
        private_certificate_model_json['private_key'] = 'testString'

        # Construct a model instance of PrivateCertificate by calling from_dict on the json representation
        private_certificate_model = PrivateCertificate.from_dict(private_certificate_model_json)
        assert private_certificate_model != False

        # Construct a model instance of PrivateCertificate by calling from_dict on the json representation
        private_certificate_model_dict = PrivateCertificate.from_dict(private_certificate_model_json).__dict__
        private_certificate_model2 = PrivateCertificate(**private_certificate_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_model == private_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_model_json2 = private_certificate_model.to_dict()
        assert private_certificate_model_json2 == private_certificate_model_json


class TestModel_PrivateCertificateActionRevoke:
    """
    Test Class for PrivateCertificateActionRevoke
    """

    def test_private_certificate_action_revoke_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateActionRevoke
        """

        # Construct a json representation of a PrivateCertificateActionRevoke model
        private_certificate_action_revoke_model_json = {}
        private_certificate_action_revoke_model_json['action_type'] = 'private_cert_action_revoke_certificate'

        # Construct a model instance of PrivateCertificateActionRevoke by calling from_dict on the json representation
        private_certificate_action_revoke_model = PrivateCertificateActionRevoke.from_dict(
            private_certificate_action_revoke_model_json)
        assert private_certificate_action_revoke_model != False

        # Construct a model instance of PrivateCertificateActionRevoke by calling from_dict on the json representation
        private_certificate_action_revoke_model_dict = PrivateCertificateActionRevoke.from_dict(
            private_certificate_action_revoke_model_json).__dict__
        private_certificate_action_revoke_model2 = PrivateCertificateActionRevoke(
            **private_certificate_action_revoke_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_action_revoke_model == private_certificate_action_revoke_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_action_revoke_model_json2 = private_certificate_action_revoke_model.to_dict()
        assert private_certificate_action_revoke_model_json2 == private_certificate_action_revoke_model_json


class TestModel_PrivateCertificateActionRevokePrototype:
    """
    Test Class for PrivateCertificateActionRevokePrototype
    """

    def test_private_certificate_action_revoke_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateActionRevokePrototype
        """

        # Construct a json representation of a PrivateCertificateActionRevokePrototype model
        private_certificate_action_revoke_prototype_model_json = {}
        private_certificate_action_revoke_prototype_model_json['action_type'] = 'private_cert_action_revoke_certificate'

        # Construct a model instance of PrivateCertificateActionRevokePrototype by calling from_dict on the json representation
        private_certificate_action_revoke_prototype_model = PrivateCertificateActionRevokePrototype.from_dict(
            private_certificate_action_revoke_prototype_model_json)
        assert private_certificate_action_revoke_prototype_model != False

        # Construct a model instance of PrivateCertificateActionRevokePrototype by calling from_dict on the json representation
        private_certificate_action_revoke_prototype_model_dict = PrivateCertificateActionRevokePrototype.from_dict(
            private_certificate_action_revoke_prototype_model_json).__dict__
        private_certificate_action_revoke_prototype_model2 = PrivateCertificateActionRevokePrototype(
            **private_certificate_action_revoke_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_action_revoke_prototype_model == private_certificate_action_revoke_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_action_revoke_prototype_model_json2 = private_certificate_action_revoke_prototype_model.to_dict()
        assert private_certificate_action_revoke_prototype_model_json2 == private_certificate_action_revoke_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionRevoke:
    """
    Test Class for PrivateCertificateConfigurationActionRevoke
    """

    def test_private_certificate_configuration_action_revoke_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRevoke
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionRevoke model
        private_certificate_configuration_action_revoke_model_json = {}
        private_certificate_configuration_action_revoke_model_json[
            'action_type'] = 'private_cert_configuration_action_revoke_ca_certificate'

        # Construct a model instance of PrivateCertificateConfigurationActionRevoke by calling from_dict on the json representation
        private_certificate_configuration_action_revoke_model = PrivateCertificateConfigurationActionRevoke.from_dict(
            private_certificate_configuration_action_revoke_model_json)
        assert private_certificate_configuration_action_revoke_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRevoke by calling from_dict on the json representation
        private_certificate_configuration_action_revoke_model_dict = PrivateCertificateConfigurationActionRevoke.from_dict(
            private_certificate_configuration_action_revoke_model_json).__dict__
        private_certificate_configuration_action_revoke_model2 = PrivateCertificateConfigurationActionRevoke(
            **private_certificate_configuration_action_revoke_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_revoke_model == private_certificate_configuration_action_revoke_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_revoke_model_json2 = private_certificate_configuration_action_revoke_model.to_dict()
        assert private_certificate_configuration_action_revoke_model_json2 == private_certificate_configuration_action_revoke_model_json


class TestModel_PrivateCertificateConfigurationActionRevokePrototype:
    """
    Test Class for PrivateCertificateConfigurationActionRevokePrototype
    """

    def test_private_certificate_configuration_action_revoke_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRevokePrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionRevokePrototype model
        private_certificate_configuration_action_revoke_prototype_model_json = {}
        private_certificate_configuration_action_revoke_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_revoke_ca_certificate'

        # Construct a model instance of PrivateCertificateConfigurationActionRevokePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_revoke_prototype_model = PrivateCertificateConfigurationActionRevokePrototype.from_dict(
            private_certificate_configuration_action_revoke_prototype_model_json)
        assert private_certificate_configuration_action_revoke_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRevokePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_revoke_prototype_model_dict = PrivateCertificateConfigurationActionRevokePrototype.from_dict(
            private_certificate_configuration_action_revoke_prototype_model_json).__dict__
        private_certificate_configuration_action_revoke_prototype_model2 = PrivateCertificateConfigurationActionRevokePrototype(
            **private_certificate_configuration_action_revoke_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_revoke_prototype_model == private_certificate_configuration_action_revoke_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_revoke_prototype_model_json2 = private_certificate_configuration_action_revoke_prototype_model.to_dict()
        assert private_certificate_configuration_action_revoke_prototype_model_json2 == private_certificate_configuration_action_revoke_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionRotate:
    """
    Test Class for PrivateCertificateConfigurationActionRotate
    """

    def test_private_certificate_configuration_action_rotate_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRotate
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_configuration_rotate_action_model = {}  # PrivateCertificateConfigurationRotateAction
        private_certificate_configuration_rotate_action_model['common_name'] = 'localhost'
        private_certificate_configuration_rotate_action_model['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_configuration_rotate_action_model['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_rotate_action_model['uri_sans'] = 'testString'
        private_certificate_configuration_rotate_action_model['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_rotate_action_model['format'] = 'pem'
        private_certificate_configuration_rotate_action_model['max_path_length'] = -1
        private_certificate_configuration_rotate_action_model['exclude_cn_from_sans'] = True
        private_certificate_configuration_rotate_action_model['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_rotate_action_model['use_csr_values'] = True
        private_certificate_configuration_rotate_action_model['ou'] = ['testString']
        private_certificate_configuration_rotate_action_model['organization'] = ['testString']
        private_certificate_configuration_rotate_action_model['country'] = ['testString']
        private_certificate_configuration_rotate_action_model['locality'] = ['testString']
        private_certificate_configuration_rotate_action_model['province'] = ['testString']
        private_certificate_configuration_rotate_action_model['street_address'] = ['testString']
        private_certificate_configuration_rotate_action_model['postal_code'] = ['testString']
        private_certificate_configuration_rotate_action_model[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_rotate_action_model['csr'] = 'testString'

        # Construct a json representation of a PrivateCertificateConfigurationActionRotate model
        private_certificate_configuration_action_rotate_model_json = {}
        private_certificate_configuration_action_rotate_model_json[
            'action_type'] = 'private_cert_configuration_action_rotate_intermediate'
        private_certificate_configuration_action_rotate_model_json['name'] = 'example-intermediate-CA'
        private_certificate_configuration_action_rotate_model_json[
            'config'] = private_certificate_configuration_rotate_action_model

        # Construct a model instance of PrivateCertificateConfigurationActionRotate by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_model = PrivateCertificateConfigurationActionRotate.from_dict(
            private_certificate_configuration_action_rotate_model_json)
        assert private_certificate_configuration_action_rotate_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRotate by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_model_dict = PrivateCertificateConfigurationActionRotate.from_dict(
            private_certificate_configuration_action_rotate_model_json).__dict__
        private_certificate_configuration_action_rotate_model2 = PrivateCertificateConfigurationActionRotate(
            **private_certificate_configuration_action_rotate_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_rotate_model == private_certificate_configuration_action_rotate_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_rotate_model_json2 = private_certificate_configuration_action_rotate_model.to_dict()
        assert private_certificate_configuration_action_rotate_model_json2 == private_certificate_configuration_action_rotate_model_json


class TestModel_PrivateCertificateConfigurationActionRotateCRL:
    """
    Test Class for PrivateCertificateConfigurationActionRotateCRL
    """

    def test_private_certificate_configuration_action_rotate_crl_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRotateCRL
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionRotateCRL model
        private_certificate_configuration_action_rotate_crl_model_json = {}
        private_certificate_configuration_action_rotate_crl_model_json[
            'action_type'] = 'private_cert_configuration_action_rotate_crl'
        private_certificate_configuration_action_rotate_crl_model_json['success'] = True

        # Construct a model instance of PrivateCertificateConfigurationActionRotateCRL by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_crl_model = PrivateCertificateConfigurationActionRotateCRL.from_dict(
            private_certificate_configuration_action_rotate_crl_model_json)
        assert private_certificate_configuration_action_rotate_crl_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRotateCRL by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_crl_model_dict = PrivateCertificateConfigurationActionRotateCRL.from_dict(
            private_certificate_configuration_action_rotate_crl_model_json).__dict__
        private_certificate_configuration_action_rotate_crl_model2 = PrivateCertificateConfigurationActionRotateCRL(
            **private_certificate_configuration_action_rotate_crl_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_rotate_crl_model == private_certificate_configuration_action_rotate_crl_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_rotate_crl_model_json2 = private_certificate_configuration_action_rotate_crl_model.to_dict()
        assert private_certificate_configuration_action_rotate_crl_model_json2 == private_certificate_configuration_action_rotate_crl_model_json


class TestModel_PrivateCertificateConfigurationActionRotateCRLPrototype:
    """
    Test Class for PrivateCertificateConfigurationActionRotateCRLPrototype
    """

    def test_private_certificate_configuration_action_rotate_crl_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRotateCRLPrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionRotateCRLPrototype model
        private_certificate_configuration_action_rotate_crl_prototype_model_json = {}
        private_certificate_configuration_action_rotate_crl_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_rotate_crl'

        # Construct a model instance of PrivateCertificateConfigurationActionRotateCRLPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_crl_prototype_model = PrivateCertificateConfigurationActionRotateCRLPrototype.from_dict(
            private_certificate_configuration_action_rotate_crl_prototype_model_json)
        assert private_certificate_configuration_action_rotate_crl_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRotateCRLPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_crl_prototype_model_dict = PrivateCertificateConfigurationActionRotateCRLPrototype.from_dict(
            private_certificate_configuration_action_rotate_crl_prototype_model_json).__dict__
        private_certificate_configuration_action_rotate_crl_prototype_model2 = PrivateCertificateConfigurationActionRotateCRLPrototype(
            **private_certificate_configuration_action_rotate_crl_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_rotate_crl_prototype_model == private_certificate_configuration_action_rotate_crl_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_rotate_crl_prototype_model_json2 = private_certificate_configuration_action_rotate_crl_prototype_model.to_dict()
        assert private_certificate_configuration_action_rotate_crl_prototype_model_json2 == private_certificate_configuration_action_rotate_crl_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionRotatePrototype:
    """
    Test Class for PrivateCertificateConfigurationActionRotatePrototype
    """

    def test_private_certificate_configuration_action_rotate_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionRotatePrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionRotatePrototype model
        private_certificate_configuration_action_rotate_prototype_model_json = {}
        private_certificate_configuration_action_rotate_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_rotate_intermediate'

        # Construct a model instance of PrivateCertificateConfigurationActionRotatePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_prototype_model = PrivateCertificateConfigurationActionRotatePrototype.from_dict(
            private_certificate_configuration_action_rotate_prototype_model_json)
        assert private_certificate_configuration_action_rotate_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionRotatePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_rotate_prototype_model_dict = PrivateCertificateConfigurationActionRotatePrototype.from_dict(
            private_certificate_configuration_action_rotate_prototype_model_json).__dict__
        private_certificate_configuration_action_rotate_prototype_model2 = PrivateCertificateConfigurationActionRotatePrototype(
            **private_certificate_configuration_action_rotate_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_rotate_prototype_model == private_certificate_configuration_action_rotate_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_rotate_prototype_model_json2 = private_certificate_configuration_action_rotate_prototype_model.to_dict()
        assert private_certificate_configuration_action_rotate_prototype_model_json2 == private_certificate_configuration_action_rotate_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionSetSigned:
    """
    Test Class for PrivateCertificateConfigurationActionSetSigned
    """

    def test_private_certificate_configuration_action_set_signed_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSetSigned
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSetSigned model
        private_certificate_configuration_action_set_signed_model_json = {}
        private_certificate_configuration_action_set_signed_model_json[
            'action_type'] = 'private_cert_configuration_action_set_signed'
        private_certificate_configuration_action_set_signed_model_json['certificate'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationActionSetSigned by calling from_dict on the json representation
        private_certificate_configuration_action_set_signed_model = PrivateCertificateConfigurationActionSetSigned.from_dict(
            private_certificate_configuration_action_set_signed_model_json)
        assert private_certificate_configuration_action_set_signed_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSetSigned by calling from_dict on the json representation
        private_certificate_configuration_action_set_signed_model_dict = PrivateCertificateConfigurationActionSetSigned.from_dict(
            private_certificate_configuration_action_set_signed_model_json).__dict__
        private_certificate_configuration_action_set_signed_model2 = PrivateCertificateConfigurationActionSetSigned(
            **private_certificate_configuration_action_set_signed_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_set_signed_model == private_certificate_configuration_action_set_signed_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_set_signed_model_json2 = private_certificate_configuration_action_set_signed_model.to_dict()
        assert private_certificate_configuration_action_set_signed_model_json2 == private_certificate_configuration_action_set_signed_model_json


class TestModel_PrivateCertificateConfigurationActionSetSignedPrototype:
    """
    Test Class for PrivateCertificateConfigurationActionSetSignedPrototype
    """

    def test_private_certificate_configuration_action_set_signed_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSetSignedPrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSetSignedPrototype model
        private_certificate_configuration_action_set_signed_prototype_model_json = {}
        private_certificate_configuration_action_set_signed_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_set_signed'
        private_certificate_configuration_action_set_signed_prototype_model_json['certificate'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationActionSetSignedPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_set_signed_prototype_model = PrivateCertificateConfigurationActionSetSignedPrototype.from_dict(
            private_certificate_configuration_action_set_signed_prototype_model_json)
        assert private_certificate_configuration_action_set_signed_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSetSignedPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_set_signed_prototype_model_dict = PrivateCertificateConfigurationActionSetSignedPrototype.from_dict(
            private_certificate_configuration_action_set_signed_prototype_model_json).__dict__
        private_certificate_configuration_action_set_signed_prototype_model2 = PrivateCertificateConfigurationActionSetSignedPrototype(
            **private_certificate_configuration_action_set_signed_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_set_signed_prototype_model == private_certificate_configuration_action_set_signed_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_set_signed_prototype_model_json2 = private_certificate_configuration_action_set_signed_prototype_model.to_dict()
        assert private_certificate_configuration_action_set_signed_prototype_model_json2 == private_certificate_configuration_action_set_signed_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionSignCSR:
    """
    Test Class for PrivateCertificateConfigurationActionSignCSR
    """

    def test_private_certificate_configuration_action_sign_csr_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSignCSR
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSignCSR model
        private_certificate_configuration_action_sign_csr_model_json = {}
        private_certificate_configuration_action_sign_csr_model_json['common_name'] = 'localhost'
        private_certificate_configuration_action_sign_csr_model_json['alt_names'] = ['s1.example.com',
                                                                                     '*.s2.example.com']
        private_certificate_configuration_action_sign_csr_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_action_sign_csr_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_action_sign_csr_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_action_sign_csr_model_json['ttl'] = '12h'
        private_certificate_configuration_action_sign_csr_model_json['format'] = 'pem'
        private_certificate_configuration_action_sign_csr_model_json['max_path_length'] = -1
        private_certificate_configuration_action_sign_csr_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_action_sign_csr_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['use_csr_values'] = True
        private_certificate_configuration_action_sign_csr_model_json['ou'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['organization'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['country'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['locality'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['province'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['street_address'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json['postal_code'] = ['testString']
        private_certificate_configuration_action_sign_csr_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_action_sign_csr_model_json[
            'action_type'] = 'private_cert_configuration_action_sign_csr'
        private_certificate_configuration_action_sign_csr_model_json['csr'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationActionSignCSR by calling from_dict on the json representation
        private_certificate_configuration_action_sign_csr_model = PrivateCertificateConfigurationActionSignCSR.from_dict(
            private_certificate_configuration_action_sign_csr_model_json)
        assert private_certificate_configuration_action_sign_csr_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSignCSR by calling from_dict on the json representation
        private_certificate_configuration_action_sign_csr_model_dict = PrivateCertificateConfigurationActionSignCSR.from_dict(
            private_certificate_configuration_action_sign_csr_model_json).__dict__
        private_certificate_configuration_action_sign_csr_model2 = PrivateCertificateConfigurationActionSignCSR(
            **private_certificate_configuration_action_sign_csr_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_sign_csr_model == private_certificate_configuration_action_sign_csr_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_sign_csr_model_json2 = private_certificate_configuration_action_sign_csr_model.to_dict()
        assert private_certificate_configuration_action_sign_csr_model_json2 == private_certificate_configuration_action_sign_csr_model_json


class TestModel_PrivateCertificateConfigurationActionSignCSRPrototype:
    """
    Test Class for PrivateCertificateConfigurationActionSignCSRPrototype
    """

    def test_private_certificate_configuration_action_sign_csr_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSignCSRPrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSignCSRPrototype model
        private_certificate_configuration_action_sign_csr_prototype_model_json = {}
        private_certificate_configuration_action_sign_csr_prototype_model_json['common_name'] = 'localhost'
        private_certificate_configuration_action_sign_csr_prototype_model_json['alt_names'] = ['s1.example.com',
                                                                                               '*.s2.example.com']
        private_certificate_configuration_action_sign_csr_prototype_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_action_sign_csr_prototype_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_action_sign_csr_prototype_model_json['other_sans'] = [
            '2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_action_sign_csr_prototype_model_json['ttl'] = '12h'
        private_certificate_configuration_action_sign_csr_prototype_model_json['format'] = 'pem'
        private_certificate_configuration_action_sign_csr_prototype_model_json['max_path_length'] = -1
        private_certificate_configuration_action_sign_csr_prototype_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_action_sign_csr_prototype_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['use_csr_values'] = True
        private_certificate_configuration_action_sign_csr_prototype_model_json['ou'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['organization'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['country'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['locality'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['province'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['street_address'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json['postal_code'] = ['testString']
        private_certificate_configuration_action_sign_csr_prototype_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_action_sign_csr_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_sign_csr'
        private_certificate_configuration_action_sign_csr_prototype_model_json['csr'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationActionSignCSRPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_sign_csr_prototype_model = PrivateCertificateConfigurationActionSignCSRPrototype.from_dict(
            private_certificate_configuration_action_sign_csr_prototype_model_json)
        assert private_certificate_configuration_action_sign_csr_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSignCSRPrototype by calling from_dict on the json representation
        private_certificate_configuration_action_sign_csr_prototype_model_dict = PrivateCertificateConfigurationActionSignCSRPrototype.from_dict(
            private_certificate_configuration_action_sign_csr_prototype_model_json).__dict__
        private_certificate_configuration_action_sign_csr_prototype_model2 = PrivateCertificateConfigurationActionSignCSRPrototype(
            **private_certificate_configuration_action_sign_csr_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_sign_csr_prototype_model == private_certificate_configuration_action_sign_csr_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_sign_csr_prototype_model_json2 = private_certificate_configuration_action_sign_csr_prototype_model.to_dict()
        assert private_certificate_configuration_action_sign_csr_prototype_model_json2 == private_certificate_configuration_action_sign_csr_prototype_model_json


class TestModel_PrivateCertificateConfigurationActionSignIntermediate:
    """
    Test Class for PrivateCertificateConfigurationActionSignIntermediate
    """

    def test_private_certificate_configuration_action_sign_intermediate_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSignIntermediate
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSignIntermediate model
        private_certificate_configuration_action_sign_intermediate_model_json = {}
        private_certificate_configuration_action_sign_intermediate_model_json['common_name'] = 'localhost'
        private_certificate_configuration_action_sign_intermediate_model_json['alt_names'] = ['s1.example.com',
                                                                                              '*.s2.example.com']
        private_certificate_configuration_action_sign_intermediate_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_action_sign_intermediate_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_action_sign_intermediate_model_json['other_sans'] = [
            '2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_action_sign_intermediate_model_json['ttl'] = '12h'
        private_certificate_configuration_action_sign_intermediate_model_json['format'] = 'pem'
        private_certificate_configuration_action_sign_intermediate_model_json['max_path_length'] = -1
        private_certificate_configuration_action_sign_intermediate_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_action_sign_intermediate_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['use_csr_values'] = True
        private_certificate_configuration_action_sign_intermediate_model_json['ou'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['organization'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['country'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['locality'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['province'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['street_address'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json['postal_code'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_action_sign_intermediate_model_json[
            'action_type'] = 'private_cert_configuration_action_sign_intermediate'
        private_certificate_configuration_action_sign_intermediate_model_json[
            'intermediate_certificate_authority'] = 'example-intermediate-CA'

        # Construct a model instance of PrivateCertificateConfigurationActionSignIntermediate by calling from_dict on the json representation
        private_certificate_configuration_action_sign_intermediate_model = PrivateCertificateConfigurationActionSignIntermediate.from_dict(
            private_certificate_configuration_action_sign_intermediate_model_json)
        assert private_certificate_configuration_action_sign_intermediate_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSignIntermediate by calling from_dict on the json representation
        private_certificate_configuration_action_sign_intermediate_model_dict = PrivateCertificateConfigurationActionSignIntermediate.from_dict(
            private_certificate_configuration_action_sign_intermediate_model_json).__dict__
        private_certificate_configuration_action_sign_intermediate_model2 = PrivateCertificateConfigurationActionSignIntermediate(
            **private_certificate_configuration_action_sign_intermediate_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_sign_intermediate_model == private_certificate_configuration_action_sign_intermediate_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_sign_intermediate_model_json2 = private_certificate_configuration_action_sign_intermediate_model.to_dict()
        assert private_certificate_configuration_action_sign_intermediate_model_json2 == private_certificate_configuration_action_sign_intermediate_model_json


class TestModel_PrivateCertificateConfigurationActionSignIntermediatePrototype:
    """
    Test Class for PrivateCertificateConfigurationActionSignIntermediatePrototype
    """

    def test_private_certificate_configuration_action_sign_intermediate_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationActionSignIntermediatePrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationActionSignIntermediatePrototype model
        private_certificate_configuration_action_sign_intermediate_prototype_model_json = {}
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['common_name'] = 'localhost'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['alt_names'] = [
            's1.example.com', '*.s2.example.com']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['other_sans'] = [
            '2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['ttl'] = '12h'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['format'] = 'pem'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['max_path_length'] = -1
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['permitted_dns_domains'] = [
            'testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['use_csr_values'] = True
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['ou'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['organization'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['country'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['locality'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['province'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['street_address'] = [
            'testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json['postal_code'] = ['testString']
        private_certificate_configuration_action_sign_intermediate_prototype_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json[
            'action_type'] = 'private_cert_configuration_action_sign_intermediate'
        private_certificate_configuration_action_sign_intermediate_prototype_model_json[
            'intermediate_certificate_authority'] = 'example-intermediate-CA'

        # Construct a model instance of PrivateCertificateConfigurationActionSignIntermediatePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_sign_intermediate_prototype_model = PrivateCertificateConfigurationActionSignIntermediatePrototype.from_dict(
            private_certificate_configuration_action_sign_intermediate_prototype_model_json)
        assert private_certificate_configuration_action_sign_intermediate_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationActionSignIntermediatePrototype by calling from_dict on the json representation
        private_certificate_configuration_action_sign_intermediate_prototype_model_dict = PrivateCertificateConfigurationActionSignIntermediatePrototype.from_dict(
            private_certificate_configuration_action_sign_intermediate_prototype_model_json).__dict__
        private_certificate_configuration_action_sign_intermediate_prototype_model2 = PrivateCertificateConfigurationActionSignIntermediatePrototype(
            **private_certificate_configuration_action_sign_intermediate_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_action_sign_intermediate_prototype_model == private_certificate_configuration_action_sign_intermediate_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_action_sign_intermediate_prototype_model_json2 = private_certificate_configuration_action_sign_intermediate_prototype_model.to_dict()
        assert private_certificate_configuration_action_sign_intermediate_prototype_model_json2 == private_certificate_configuration_action_sign_intermediate_prototype_model_json


class TestModel_PrivateCertificateConfigurationCACertificate:
    """
    Test Class for PrivateCertificateConfigurationCACertificate
    """

    def test_private_certificate_configuration_ca_certificate_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationCACertificate
        """

        # Construct a json representation of a PrivateCertificateConfigurationCACertificate model
        private_certificate_configuration_ca_certificate_model_json = {}
        private_certificate_configuration_ca_certificate_model_json['certificate'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationCACertificate by calling from_dict on the json representation
        private_certificate_configuration_ca_certificate_model = PrivateCertificateConfigurationCACertificate.from_dict(
            private_certificate_configuration_ca_certificate_model_json)
        assert private_certificate_configuration_ca_certificate_model != False

        # Construct a model instance of PrivateCertificateConfigurationCACertificate by calling from_dict on the json representation
        private_certificate_configuration_ca_certificate_model_dict = PrivateCertificateConfigurationCACertificate.from_dict(
            private_certificate_configuration_ca_certificate_model_json).__dict__
        private_certificate_configuration_ca_certificate_model2 = PrivateCertificateConfigurationCACertificate(
            **private_certificate_configuration_ca_certificate_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_ca_certificate_model == private_certificate_configuration_ca_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_ca_certificate_model_json2 = private_certificate_configuration_ca_certificate_model.to_dict()
        assert private_certificate_configuration_ca_certificate_model_json2 == private_certificate_configuration_ca_certificate_model_json


class TestModel_PrivateCertificateConfigurationIntermediateCA:
    """
    Test Class for PrivateCertificateConfigurationIntermediateCA
    """

    def test_private_certificate_configuration_intermediate_ca_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationIntermediateCA
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        private_certificate_ca_data_model = {}  # PrivateCertificateConfigurationIntermediateCACSR
        private_certificate_ca_data_model['csr'] = 'testString'
        private_certificate_ca_data_model['private_key'] = 'testString'
        private_certificate_ca_data_model['private_key_type'] = 'rsa'

        # Construct a json representation of a PrivateCertificateConfigurationIntermediateCA model
        private_certificate_configuration_intermediate_ca_model_json = {}
        private_certificate_configuration_intermediate_ca_model_json[
            'config_type'] = 'private_cert_configuration_intermediate_ca'
        private_certificate_configuration_intermediate_ca_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_intermediate_ca_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_intermediate_ca_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_intermediate_ca_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_model_json['common_name'] = 'localhost'
        private_certificate_configuration_intermediate_ca_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_intermediate_ca_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_model_json['issuer'] = 'Lets Encrypt'
        private_certificate_configuration_intermediate_ca_model_json['key_type'] = 'rsa'
        private_certificate_configuration_intermediate_ca_model_json['key_bits'] = 4096
        private_certificate_configuration_intermediate_ca_model_json['signing_method'] = 'internal'
        private_certificate_configuration_intermediate_ca_model_json[
            'crypto_key'] = private_certificate_crypto_key_model
        private_certificate_configuration_intermediate_ca_model_json['crl_disable'] = True
        private_certificate_configuration_intermediate_ca_model_json['issuing_certificates_urls_encoded'] = True
        private_certificate_configuration_intermediate_ca_model_json['alt_names'] = ['s1.example.com',
                                                                                     '*.s2.example.com']
        private_certificate_configuration_intermediate_ca_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_intermediate_ca_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_intermediate_ca_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_intermediate_ca_model_json['format'] = 'pem'
        private_certificate_configuration_intermediate_ca_model_json['private_key_format'] = 'der'
        private_certificate_configuration_intermediate_ca_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_intermediate_ca_model_json['ou'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['organization'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['country'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['locality'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['province'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['street_address'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json['postal_code'] = ['testString']
        private_certificate_configuration_intermediate_ca_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_configuration_intermediate_ca_model_json['data'] = private_certificate_ca_data_model

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCA by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_model = PrivateCertificateConfigurationIntermediateCA.from_dict(
            private_certificate_configuration_intermediate_ca_model_json)
        assert private_certificate_configuration_intermediate_ca_model != False

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCA by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_model_dict = PrivateCertificateConfigurationIntermediateCA.from_dict(
            private_certificate_configuration_intermediate_ca_model_json).__dict__
        private_certificate_configuration_intermediate_ca_model2 = PrivateCertificateConfigurationIntermediateCA(
            **private_certificate_configuration_intermediate_ca_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_intermediate_ca_model == private_certificate_configuration_intermediate_ca_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_intermediate_ca_model_json2 = private_certificate_configuration_intermediate_ca_model.to_dict()
        assert private_certificate_configuration_intermediate_ca_model_json2 == private_certificate_configuration_intermediate_ca_model_json


class TestModel_PrivateCertificateConfigurationIntermediateCACSR:
    """
    Test Class for PrivateCertificateConfigurationIntermediateCACSR
    """

    def test_private_certificate_configuration_intermediate_cacsr_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationIntermediateCACSR
        """

        # Construct a json representation of a PrivateCertificateConfigurationIntermediateCACSR model
        private_certificate_configuration_intermediate_cacsr_model_json = {}
        private_certificate_configuration_intermediate_cacsr_model_json['csr'] = 'testString'
        private_certificate_configuration_intermediate_cacsr_model_json['private_key'] = 'testString'
        private_certificate_configuration_intermediate_cacsr_model_json['private_key_type'] = 'rsa'

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCACSR by calling from_dict on the json representation
        private_certificate_configuration_intermediate_cacsr_model = PrivateCertificateConfigurationIntermediateCACSR.from_dict(
            private_certificate_configuration_intermediate_cacsr_model_json)
        assert private_certificate_configuration_intermediate_cacsr_model != False

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCACSR by calling from_dict on the json representation
        private_certificate_configuration_intermediate_cacsr_model_dict = PrivateCertificateConfigurationIntermediateCACSR.from_dict(
            private_certificate_configuration_intermediate_cacsr_model_json).__dict__
        private_certificate_configuration_intermediate_cacsr_model2 = PrivateCertificateConfigurationIntermediateCACSR(
            **private_certificate_configuration_intermediate_cacsr_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_intermediate_cacsr_model == private_certificate_configuration_intermediate_cacsr_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_intermediate_cacsr_model_json2 = private_certificate_configuration_intermediate_cacsr_model.to_dict()
        assert private_certificate_configuration_intermediate_cacsr_model_json2 == private_certificate_configuration_intermediate_cacsr_model_json


class TestModel_PrivateCertificateConfigurationIntermediateCAMetadata:
    """
    Test Class for PrivateCertificateConfigurationIntermediateCAMetadata
    """

    def test_private_certificate_configuration_intermediate_ca_metadata_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationIntermediateCAMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        # Construct a json representation of a PrivateCertificateConfigurationIntermediateCAMetadata model
        private_certificate_configuration_intermediate_ca_metadata_model_json = {}
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'config_type'] = 'private_cert_configuration_intermediate_ca'
        private_certificate_configuration_intermediate_ca_metadata_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_intermediate_ca_metadata_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_metadata_model_json['common_name'] = 'localhost'
        private_certificate_configuration_intermediate_ca_metadata_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_configuration_intermediate_ca_metadata_model_json['issuer'] = 'Lets Encrypt'
        private_certificate_configuration_intermediate_ca_metadata_model_json['key_type'] = 'rsa'
        private_certificate_configuration_intermediate_ca_metadata_model_json['key_bits'] = 4096
        private_certificate_configuration_intermediate_ca_metadata_model_json['signing_method'] = 'internal'
        private_certificate_configuration_intermediate_ca_metadata_model_json[
            'crypto_key'] = private_certificate_crypto_key_model

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAMetadata by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_metadata_model = PrivateCertificateConfigurationIntermediateCAMetadata.from_dict(
            private_certificate_configuration_intermediate_ca_metadata_model_json)
        assert private_certificate_configuration_intermediate_ca_metadata_model != False

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAMetadata by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_metadata_model_dict = PrivateCertificateConfigurationIntermediateCAMetadata.from_dict(
            private_certificate_configuration_intermediate_ca_metadata_model_json).__dict__
        private_certificate_configuration_intermediate_ca_metadata_model2 = PrivateCertificateConfigurationIntermediateCAMetadata(
            **private_certificate_configuration_intermediate_ca_metadata_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_intermediate_ca_metadata_model == private_certificate_configuration_intermediate_ca_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_intermediate_ca_metadata_model_json2 = private_certificate_configuration_intermediate_ca_metadata_model.to_dict()
        assert private_certificate_configuration_intermediate_ca_metadata_model_json2 == private_certificate_configuration_intermediate_ca_metadata_model_json


class TestModel_PrivateCertificateConfigurationIntermediateCAPatch:
    """
    Test Class for PrivateCertificateConfigurationIntermediateCAPatch
    """

    def test_private_certificate_configuration_intermediate_ca_patch_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationIntermediateCAPatch
        """

        # Construct a json representation of a PrivateCertificateConfigurationIntermediateCAPatch model
        private_certificate_configuration_intermediate_ca_patch_model_json = {}
        private_certificate_configuration_intermediate_ca_patch_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_intermediate_ca_patch_model_json['crl_expiry'] = '72h'
        private_certificate_configuration_intermediate_ca_patch_model_json['crl_disable'] = True
        private_certificate_configuration_intermediate_ca_patch_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_intermediate_ca_patch_model_json['issuing_certificates_urls_encoded'] = True

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAPatch by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_patch_model = PrivateCertificateConfigurationIntermediateCAPatch.from_dict(
            private_certificate_configuration_intermediate_ca_patch_model_json)
        assert private_certificate_configuration_intermediate_ca_patch_model != False

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAPatch by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_patch_model_dict = PrivateCertificateConfigurationIntermediateCAPatch.from_dict(
            private_certificate_configuration_intermediate_ca_patch_model_json).__dict__
        private_certificate_configuration_intermediate_ca_patch_model2 = PrivateCertificateConfigurationIntermediateCAPatch(
            **private_certificate_configuration_intermediate_ca_patch_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_intermediate_ca_patch_model == private_certificate_configuration_intermediate_ca_patch_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_intermediate_ca_patch_model_json2 = private_certificate_configuration_intermediate_ca_patch_model.to_dict()
        assert private_certificate_configuration_intermediate_ca_patch_model_json2 == private_certificate_configuration_intermediate_ca_patch_model_json


class TestModel_PrivateCertificateConfigurationIntermediateCAPrototype:
    """
    Test Class for PrivateCertificateConfigurationIntermediateCAPrototype
    """

    def test_private_certificate_configuration_intermediate_ca_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationIntermediateCAPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        # Construct a json representation of a PrivateCertificateConfigurationIntermediateCAPrototype model
        private_certificate_configuration_intermediate_ca_prototype_model_json = {}
        private_certificate_configuration_intermediate_ca_prototype_model_json[
            'config_type'] = 'private_cert_configuration_intermediate_ca'
        private_certificate_configuration_intermediate_ca_prototype_model_json['name'] = 'my-example-engine-config'
        private_certificate_configuration_intermediate_ca_prototype_model_json[
            'crypto_key'] = private_certificate_crypto_key_model
        private_certificate_configuration_intermediate_ca_prototype_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_intermediate_ca_prototype_model_json['signing_method'] = 'internal'
        private_certificate_configuration_intermediate_ca_prototype_model_json['issuer'] = 'Lets Encrypt'
        private_certificate_configuration_intermediate_ca_prototype_model_json['crl_expiry'] = '72h'
        private_certificate_configuration_intermediate_ca_prototype_model_json['crl_disable'] = True
        private_certificate_configuration_intermediate_ca_prototype_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_intermediate_ca_prototype_model_json[
            'issuing_certificates_urls_encoded'] = True
        private_certificate_configuration_intermediate_ca_prototype_model_json['common_name'] = 'localhost'
        private_certificate_configuration_intermediate_ca_prototype_model_json['alt_names'] = ['s1.example.com',
                                                                                               '*.s2.example.com']
        private_certificate_configuration_intermediate_ca_prototype_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_intermediate_ca_prototype_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_intermediate_ca_prototype_model_json['other_sans'] = [
            '2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_intermediate_ca_prototype_model_json['format'] = 'pem'
        private_certificate_configuration_intermediate_ca_prototype_model_json['private_key_format'] = 'der'
        private_certificate_configuration_intermediate_ca_prototype_model_json['key_type'] = 'rsa'
        private_certificate_configuration_intermediate_ca_prototype_model_json['key_bits'] = 4096
        private_certificate_configuration_intermediate_ca_prototype_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_intermediate_ca_prototype_model_json['ou'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['organization'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['country'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['locality'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['province'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['street_address'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json['postal_code'] = ['testString']
        private_certificate_configuration_intermediate_ca_prototype_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAPrototype by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_prototype_model = PrivateCertificateConfigurationIntermediateCAPrototype.from_dict(
            private_certificate_configuration_intermediate_ca_prototype_model_json)
        assert private_certificate_configuration_intermediate_ca_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationIntermediateCAPrototype by calling from_dict on the json representation
        private_certificate_configuration_intermediate_ca_prototype_model_dict = PrivateCertificateConfigurationIntermediateCAPrototype.from_dict(
            private_certificate_configuration_intermediate_ca_prototype_model_json).__dict__
        private_certificate_configuration_intermediate_ca_prototype_model2 = PrivateCertificateConfigurationIntermediateCAPrototype(
            **private_certificate_configuration_intermediate_ca_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_intermediate_ca_prototype_model == private_certificate_configuration_intermediate_ca_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_intermediate_ca_prototype_model_json2 = private_certificate_configuration_intermediate_ca_prototype_model.to_dict()
        assert private_certificate_configuration_intermediate_ca_prototype_model_json2 == private_certificate_configuration_intermediate_ca_prototype_model_json


class TestModel_PrivateCertificateConfigurationRootCA:
    """
    Test Class for PrivateCertificateConfigurationRootCA
    """

    def test_private_certificate_configuration_root_ca_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationRootCA
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        private_certificate_ca_data_model = {}  # PrivateCertificateConfigurationIntermediateCACSR
        private_certificate_ca_data_model['csr'] = 'testString'
        private_certificate_ca_data_model['private_key'] = 'testString'
        private_certificate_ca_data_model['private_key_type'] = 'rsa'

        # Construct a json representation of a PrivateCertificateConfigurationRootCA model
        private_certificate_configuration_root_ca_model_json = {}
        private_certificate_configuration_root_ca_model_json['config_type'] = 'private_cert_configuration_root_ca'
        private_certificate_configuration_root_ca_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_root_ca_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_root_ca_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_root_ca_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_model_json['common_name'] = 'localhost'
        private_certificate_configuration_root_ca_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_root_ca_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_model_json['key_type'] = 'rsa'
        private_certificate_configuration_root_ca_model_json['key_bits'] = 4096
        private_certificate_configuration_root_ca_model_json['crypto_key'] = private_certificate_crypto_key_model
        private_certificate_configuration_root_ca_model_json['crl_disable'] = True
        private_certificate_configuration_root_ca_model_json['issuing_certificates_urls_encoded'] = True
        private_certificate_configuration_root_ca_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_configuration_root_ca_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_root_ca_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_root_ca_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_root_ca_model_json['format'] = 'pem'
        private_certificate_configuration_root_ca_model_json['private_key_format'] = 'der'
        private_certificate_configuration_root_ca_model_json['max_path_length'] = -1
        private_certificate_configuration_root_ca_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_root_ca_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_root_ca_model_json['ou'] = ['testString']
        private_certificate_configuration_root_ca_model_json['organization'] = ['testString']
        private_certificate_configuration_root_ca_model_json['country'] = ['testString']
        private_certificate_configuration_root_ca_model_json['locality'] = ['testString']
        private_certificate_configuration_root_ca_model_json['province'] = ['testString']
        private_certificate_configuration_root_ca_model_json['street_address'] = ['testString']
        private_certificate_configuration_root_ca_model_json['postal_code'] = ['testString']
        private_certificate_configuration_root_ca_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_configuration_root_ca_model_json['data'] = private_certificate_ca_data_model

        # Construct a model instance of PrivateCertificateConfigurationRootCA by calling from_dict on the json representation
        private_certificate_configuration_root_ca_model = PrivateCertificateConfigurationRootCA.from_dict(
            private_certificate_configuration_root_ca_model_json)
        assert private_certificate_configuration_root_ca_model != False

        # Construct a model instance of PrivateCertificateConfigurationRootCA by calling from_dict on the json representation
        private_certificate_configuration_root_ca_model_dict = PrivateCertificateConfigurationRootCA.from_dict(
            private_certificate_configuration_root_ca_model_json).__dict__
        private_certificate_configuration_root_ca_model2 = PrivateCertificateConfigurationRootCA(
            **private_certificate_configuration_root_ca_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_root_ca_model == private_certificate_configuration_root_ca_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_root_ca_model_json2 = private_certificate_configuration_root_ca_model.to_dict()
        assert private_certificate_configuration_root_ca_model_json2 == private_certificate_configuration_root_ca_model_json


class TestModel_PrivateCertificateConfigurationRootCAMetadata:
    """
    Test Class for PrivateCertificateConfigurationRootCAMetadata
    """

    def test_private_certificate_configuration_root_ca_metadata_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationRootCAMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        # Construct a json representation of a PrivateCertificateConfigurationRootCAMetadata model
        private_certificate_configuration_root_ca_metadata_model_json = {}
        private_certificate_configuration_root_ca_metadata_model_json[
            'config_type'] = 'private_cert_configuration_root_ca'
        private_certificate_configuration_root_ca_metadata_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_root_ca_metadata_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_root_ca_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_root_ca_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_metadata_model_json['common_name'] = 'localhost'
        private_certificate_configuration_root_ca_metadata_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_root_ca_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_configuration_root_ca_metadata_model_json['key_type'] = 'rsa'
        private_certificate_configuration_root_ca_metadata_model_json['key_bits'] = 4096
        private_certificate_configuration_root_ca_metadata_model_json[
            'crypto_key'] = private_certificate_crypto_key_model

        # Construct a model instance of PrivateCertificateConfigurationRootCAMetadata by calling from_dict on the json representation
        private_certificate_configuration_root_ca_metadata_model = PrivateCertificateConfigurationRootCAMetadata.from_dict(
            private_certificate_configuration_root_ca_metadata_model_json)
        assert private_certificate_configuration_root_ca_metadata_model != False

        # Construct a model instance of PrivateCertificateConfigurationRootCAMetadata by calling from_dict on the json representation
        private_certificate_configuration_root_ca_metadata_model_dict = PrivateCertificateConfigurationRootCAMetadata.from_dict(
            private_certificate_configuration_root_ca_metadata_model_json).__dict__
        private_certificate_configuration_root_ca_metadata_model2 = PrivateCertificateConfigurationRootCAMetadata(
            **private_certificate_configuration_root_ca_metadata_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_root_ca_metadata_model == private_certificate_configuration_root_ca_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_root_ca_metadata_model_json2 = private_certificate_configuration_root_ca_metadata_model.to_dict()
        assert private_certificate_configuration_root_ca_metadata_model_json2 == private_certificate_configuration_root_ca_metadata_model_json


class TestModel_PrivateCertificateConfigurationRootCAPatch:
    """
    Test Class for PrivateCertificateConfigurationRootCAPatch
    """

    def test_private_certificate_configuration_root_ca_patch_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationRootCAPatch
        """

        # Construct a json representation of a PrivateCertificateConfigurationRootCAPatch model
        private_certificate_configuration_root_ca_patch_model_json = {}
        private_certificate_configuration_root_ca_patch_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_root_ca_patch_model_json['crl_expiry'] = '72h'
        private_certificate_configuration_root_ca_patch_model_json['crl_disable'] = True
        private_certificate_configuration_root_ca_patch_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_root_ca_patch_model_json['issuing_certificates_urls_encoded'] = True

        # Construct a model instance of PrivateCertificateConfigurationRootCAPatch by calling from_dict on the json representation
        private_certificate_configuration_root_ca_patch_model = PrivateCertificateConfigurationRootCAPatch.from_dict(
            private_certificate_configuration_root_ca_patch_model_json)
        assert private_certificate_configuration_root_ca_patch_model != False

        # Construct a model instance of PrivateCertificateConfigurationRootCAPatch by calling from_dict on the json representation
        private_certificate_configuration_root_ca_patch_model_dict = PrivateCertificateConfigurationRootCAPatch.from_dict(
            private_certificate_configuration_root_ca_patch_model_json).__dict__
        private_certificate_configuration_root_ca_patch_model2 = PrivateCertificateConfigurationRootCAPatch(
            **private_certificate_configuration_root_ca_patch_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_root_ca_patch_model == private_certificate_configuration_root_ca_patch_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_root_ca_patch_model_json2 = private_certificate_configuration_root_ca_patch_model.to_dict()
        assert private_certificate_configuration_root_ca_patch_model_json2 == private_certificate_configuration_root_ca_patch_model_json


class TestModel_PrivateCertificateConfigurationRootCAPrototype:
    """
    Test Class for PrivateCertificateConfigurationRootCAPrototype
    """

    def test_private_certificate_configuration_root_ca_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationRootCAPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        private_certificate_crypto_provider_model = {}  # PrivateCertificateCryptoProviderHPCS
        private_certificate_crypto_provider_model['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_model[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_model[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_model['private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        private_certificate_crypto_key_model = {}  # PrivateCertificateCryptoKey
        private_certificate_crypto_key_model['id'] = 'ad629506-3aca-4191-b8fc-8b295ec7a19c'
        private_certificate_crypto_key_model['label'] = 'my_key'
        private_certificate_crypto_key_model['allow_generate_key'] = False
        private_certificate_crypto_key_model['provider'] = private_certificate_crypto_provider_model

        # Construct a json representation of a PrivateCertificateConfigurationRootCAPrototype model
        private_certificate_configuration_root_ca_prototype_model_json = {}
        private_certificate_configuration_root_ca_prototype_model_json[
            'config_type'] = 'private_cert_configuration_root_ca'
        private_certificate_configuration_root_ca_prototype_model_json['name'] = 'my-example-engine-config'
        private_certificate_configuration_root_ca_prototype_model_json[
            'crypto_key'] = private_certificate_crypto_key_model
        private_certificate_configuration_root_ca_prototype_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_root_ca_prototype_model_json['crl_expiry'] = '72h'
        private_certificate_configuration_root_ca_prototype_model_json['crl_disable'] = True
        private_certificate_configuration_root_ca_prototype_model_json['crl_distribution_points_encoded'] = True
        private_certificate_configuration_root_ca_prototype_model_json['issuing_certificates_urls_encoded'] = True
        private_certificate_configuration_root_ca_prototype_model_json['common_name'] = 'localhost'
        private_certificate_configuration_root_ca_prototype_model_json['alt_names'] = ['s1.example.com',
                                                                                       '*.s2.example.com']
        private_certificate_configuration_root_ca_prototype_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_configuration_root_ca_prototype_model_json['uri_sans'] = 'testString'
        private_certificate_configuration_root_ca_prototype_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_configuration_root_ca_prototype_model_json['ttl'] = '8760h'
        private_certificate_configuration_root_ca_prototype_model_json['format'] = 'pem'
        private_certificate_configuration_root_ca_prototype_model_json['private_key_format'] = 'der'
        private_certificate_configuration_root_ca_prototype_model_json['key_type'] = 'rsa'
        private_certificate_configuration_root_ca_prototype_model_json['key_bits'] = 4096
        private_certificate_configuration_root_ca_prototype_model_json['max_path_length'] = -1
        private_certificate_configuration_root_ca_prototype_model_json['exclude_cn_from_sans'] = True
        private_certificate_configuration_root_ca_prototype_model_json['permitted_dns_domains'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['ou'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['organization'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['country'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['locality'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['province'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['street_address'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json['postal_code'] = ['testString']
        private_certificate_configuration_root_ca_prototype_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'

        # Construct a model instance of PrivateCertificateConfigurationRootCAPrototype by calling from_dict on the json representation
        private_certificate_configuration_root_ca_prototype_model = PrivateCertificateConfigurationRootCAPrototype.from_dict(
            private_certificate_configuration_root_ca_prototype_model_json)
        assert private_certificate_configuration_root_ca_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationRootCAPrototype by calling from_dict on the json representation
        private_certificate_configuration_root_ca_prototype_model_dict = PrivateCertificateConfigurationRootCAPrototype.from_dict(
            private_certificate_configuration_root_ca_prototype_model_json).__dict__
        private_certificate_configuration_root_ca_prototype_model2 = PrivateCertificateConfigurationRootCAPrototype(
            **private_certificate_configuration_root_ca_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_root_ca_prototype_model == private_certificate_configuration_root_ca_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_root_ca_prototype_model_json2 = private_certificate_configuration_root_ca_prototype_model.to_dict()
        assert private_certificate_configuration_root_ca_prototype_model_json2 == private_certificate_configuration_root_ca_prototype_model_json


class TestModel_PrivateCertificateConfigurationTemplate:
    """
    Test Class for PrivateCertificateConfigurationTemplate
    """

    def test_private_certificate_configuration_template_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationTemplate
        """

        # Construct a json representation of a PrivateCertificateConfigurationTemplate model
        private_certificate_configuration_template_model_json = {}
        private_certificate_configuration_template_model_json['config_type'] = 'private_cert_configuration_template'
        private_certificate_configuration_template_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_template_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_template_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_template_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_template_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_template_model_json['certificate_authority'] = 'testString'
        private_certificate_configuration_template_model_json['allowed_secret_groups'] = 'testString'
        private_certificate_configuration_template_model_json['allow_localhost'] = True
        private_certificate_configuration_template_model_json['allowed_domains'] = ['testString']
        private_certificate_configuration_template_model_json['allowed_domains_template'] = True
        private_certificate_configuration_template_model_json['allow_bare_domains'] = True
        private_certificate_configuration_template_model_json['allow_subdomains'] = True
        private_certificate_configuration_template_model_json['allow_glob_domains'] = True
        private_certificate_configuration_template_model_json['allow_any_name'] = True
        private_certificate_configuration_template_model_json['enforce_hostnames'] = True
        private_certificate_configuration_template_model_json['allow_ip_sans'] = True
        private_certificate_configuration_template_model_json['allowed_uri_sans'] = ['testString']
        private_certificate_configuration_template_model_json['allowed_other_sans'] = ['2.5.4.5;UTF8:*']
        private_certificate_configuration_template_model_json['server_flag'] = True
        private_certificate_configuration_template_model_json['client_flag'] = True
        private_certificate_configuration_template_model_json['code_signing_flag'] = True
        private_certificate_configuration_template_model_json['email_protection_flag'] = True
        private_certificate_configuration_template_model_json['key_type'] = 'rsa'
        private_certificate_configuration_template_model_json['key_bits'] = 4096
        private_certificate_configuration_template_model_json['key_usage'] = ['DigitalSignature', 'KeyAgreement',
                                                                              'KeyEncipherment']
        private_certificate_configuration_template_model_json['ext_key_usage'] = ['testString']
        private_certificate_configuration_template_model_json['ext_key_usage_oids'] = ['testString']
        private_certificate_configuration_template_model_json['use_csr_common_name'] = True
        private_certificate_configuration_template_model_json['use_csr_sans'] = True
        private_certificate_configuration_template_model_json['ou'] = ['testString']
        private_certificate_configuration_template_model_json['organization'] = ['testString']
        private_certificate_configuration_template_model_json['country'] = ['testString']
        private_certificate_configuration_template_model_json['locality'] = ['testString']
        private_certificate_configuration_template_model_json['province'] = ['testString']
        private_certificate_configuration_template_model_json['street_address'] = ['testString']
        private_certificate_configuration_template_model_json['postal_code'] = ['testString']
        private_certificate_configuration_template_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_template_model_json['require_cn'] = True
        private_certificate_configuration_template_model_json['policy_identifiers'] = ['testString']
        private_certificate_configuration_template_model_json['basic_constraints_valid_for_non_ca'] = True

        # Construct a model instance of PrivateCertificateConfigurationTemplate by calling from_dict on the json representation
        private_certificate_configuration_template_model = PrivateCertificateConfigurationTemplate.from_dict(
            private_certificate_configuration_template_model_json)
        assert private_certificate_configuration_template_model != False

        # Construct a model instance of PrivateCertificateConfigurationTemplate by calling from_dict on the json representation
        private_certificate_configuration_template_model_dict = PrivateCertificateConfigurationTemplate.from_dict(
            private_certificate_configuration_template_model_json).__dict__
        private_certificate_configuration_template_model2 = PrivateCertificateConfigurationTemplate(
            **private_certificate_configuration_template_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_template_model == private_certificate_configuration_template_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_template_model_json2 = private_certificate_configuration_template_model.to_dict()
        assert private_certificate_configuration_template_model_json2 == private_certificate_configuration_template_model_json


class TestModel_PrivateCertificateConfigurationTemplateMetadata:
    """
    Test Class for PrivateCertificateConfigurationTemplateMetadata
    """

    def test_private_certificate_configuration_template_metadata_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationTemplateMetadata
        """

        # Construct a json representation of a PrivateCertificateConfigurationTemplateMetadata model
        private_certificate_configuration_template_metadata_model_json = {}
        private_certificate_configuration_template_metadata_model_json[
            'config_type'] = 'private_cert_configuration_template'
        private_certificate_configuration_template_metadata_model_json['name'] = 'my-secret-engine-config'
        private_certificate_configuration_template_metadata_model_json['secret_type'] = 'arbitrary'
        private_certificate_configuration_template_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_configuration_template_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_template_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_configuration_template_metadata_model_json['certificate_authority'] = 'testString'

        # Construct a model instance of PrivateCertificateConfigurationTemplateMetadata by calling from_dict on the json representation
        private_certificate_configuration_template_metadata_model = PrivateCertificateConfigurationTemplateMetadata.from_dict(
            private_certificate_configuration_template_metadata_model_json)
        assert private_certificate_configuration_template_metadata_model != False

        # Construct a model instance of PrivateCertificateConfigurationTemplateMetadata by calling from_dict on the json representation
        private_certificate_configuration_template_metadata_model_dict = PrivateCertificateConfigurationTemplateMetadata.from_dict(
            private_certificate_configuration_template_metadata_model_json).__dict__
        private_certificate_configuration_template_metadata_model2 = PrivateCertificateConfigurationTemplateMetadata(
            **private_certificate_configuration_template_metadata_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_template_metadata_model == private_certificate_configuration_template_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_template_metadata_model_json2 = private_certificate_configuration_template_metadata_model.to_dict()
        assert private_certificate_configuration_template_metadata_model_json2 == private_certificate_configuration_template_metadata_model_json


class TestModel_PrivateCertificateConfigurationTemplatePatch:
    """
    Test Class for PrivateCertificateConfigurationTemplatePatch
    """

    def test_private_certificate_configuration_template_patch_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationTemplatePatch
        """

        # Construct a json representation of a PrivateCertificateConfigurationTemplatePatch model
        private_certificate_configuration_template_patch_model_json = {}
        private_certificate_configuration_template_patch_model_json['allowed_secret_groups'] = 'testString'
        private_certificate_configuration_template_patch_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_template_patch_model_json['ttl'] = '8760h'
        private_certificate_configuration_template_patch_model_json['allow_localhost'] = True
        private_certificate_configuration_template_patch_model_json['allowed_domains'] = ['testString']
        private_certificate_configuration_template_patch_model_json['allowed_domains_template'] = True
        private_certificate_configuration_template_patch_model_json['allow_bare_domains'] = True
        private_certificate_configuration_template_patch_model_json['allow_subdomains'] = True
        private_certificate_configuration_template_patch_model_json['allow_glob_domains'] = True
        private_certificate_configuration_template_patch_model_json['allow_any_name'] = True
        private_certificate_configuration_template_patch_model_json['enforce_hostnames'] = True
        private_certificate_configuration_template_patch_model_json['allow_ip_sans'] = True
        private_certificate_configuration_template_patch_model_json['allowed_uri_sans'] = ['testString']
        private_certificate_configuration_template_patch_model_json['allowed_other_sans'] = ['2.5.4.5;UTF8:*']
        private_certificate_configuration_template_patch_model_json['server_flag'] = True
        private_certificate_configuration_template_patch_model_json['client_flag'] = True
        private_certificate_configuration_template_patch_model_json['code_signing_flag'] = True
        private_certificate_configuration_template_patch_model_json['email_protection_flag'] = True
        private_certificate_configuration_template_patch_model_json['key_type'] = 'rsa'
        private_certificate_configuration_template_patch_model_json['key_bits'] = 4096
        private_certificate_configuration_template_patch_model_json['key_usage'] = ['DigitalSignature', 'KeyAgreement',
                                                                                    'KeyEncipherment']
        private_certificate_configuration_template_patch_model_json['ext_key_usage'] = ['testString']
        private_certificate_configuration_template_patch_model_json['ext_key_usage_oids'] = ['testString']
        private_certificate_configuration_template_patch_model_json['use_csr_common_name'] = True
        private_certificate_configuration_template_patch_model_json['use_csr_sans'] = True
        private_certificate_configuration_template_patch_model_json['ou'] = ['testString']
        private_certificate_configuration_template_patch_model_json['organization'] = ['testString']
        private_certificate_configuration_template_patch_model_json['country'] = ['testString']
        private_certificate_configuration_template_patch_model_json['locality'] = ['testString']
        private_certificate_configuration_template_patch_model_json['province'] = ['testString']
        private_certificate_configuration_template_patch_model_json['street_address'] = ['testString']
        private_certificate_configuration_template_patch_model_json['postal_code'] = ['testString']
        private_certificate_configuration_template_patch_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_template_patch_model_json['require_cn'] = True
        private_certificate_configuration_template_patch_model_json['policy_identifiers'] = ['testString']
        private_certificate_configuration_template_patch_model_json['basic_constraints_valid_for_non_ca'] = True
        private_certificate_configuration_template_patch_model_json['not_before_duration'] = '30s'

        # Construct a model instance of PrivateCertificateConfigurationTemplatePatch by calling from_dict on the json representation
        private_certificate_configuration_template_patch_model = PrivateCertificateConfigurationTemplatePatch.from_dict(
            private_certificate_configuration_template_patch_model_json)
        assert private_certificate_configuration_template_patch_model != False

        # Construct a model instance of PrivateCertificateConfigurationTemplatePatch by calling from_dict on the json representation
        private_certificate_configuration_template_patch_model_dict = PrivateCertificateConfigurationTemplatePatch.from_dict(
            private_certificate_configuration_template_patch_model_json).__dict__
        private_certificate_configuration_template_patch_model2 = PrivateCertificateConfigurationTemplatePatch(
            **private_certificate_configuration_template_patch_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_template_patch_model == private_certificate_configuration_template_patch_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_template_patch_model_json2 = private_certificate_configuration_template_patch_model.to_dict()
        assert private_certificate_configuration_template_patch_model_json2 == private_certificate_configuration_template_patch_model_json


class TestModel_PrivateCertificateConfigurationTemplatePrototype:
    """
    Test Class for PrivateCertificateConfigurationTemplatePrototype
    """

    def test_private_certificate_configuration_template_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateConfigurationTemplatePrototype
        """

        # Construct a json representation of a PrivateCertificateConfigurationTemplatePrototype model
        private_certificate_configuration_template_prototype_model_json = {}
        private_certificate_configuration_template_prototype_model_json[
            'config_type'] = 'private_cert_configuration_template'
        private_certificate_configuration_template_prototype_model_json['name'] = 'my-example-engine-config'
        private_certificate_configuration_template_prototype_model_json['certificate_authority'] = 'testString'
        private_certificate_configuration_template_prototype_model_json['allowed_secret_groups'] = 'testString'
        private_certificate_configuration_template_prototype_model_json['max_ttl'] = '8760h'
        private_certificate_configuration_template_prototype_model_json['ttl'] = '8760h'
        private_certificate_configuration_template_prototype_model_json['allow_localhost'] = True
        private_certificate_configuration_template_prototype_model_json['allowed_domains'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['allowed_domains_template'] = True
        private_certificate_configuration_template_prototype_model_json['allow_bare_domains'] = True
        private_certificate_configuration_template_prototype_model_json['allow_subdomains'] = True
        private_certificate_configuration_template_prototype_model_json['allow_glob_domains'] = True
        private_certificate_configuration_template_prototype_model_json['allow_wildcard_certificates'] = True
        private_certificate_configuration_template_prototype_model_json['allow_any_name'] = True
        private_certificate_configuration_template_prototype_model_json['enforce_hostnames'] = True
        private_certificate_configuration_template_prototype_model_json['allow_ip_sans'] = True
        private_certificate_configuration_template_prototype_model_json['allowed_uri_sans'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['allowed_other_sans'] = ['2.5.4.5;UTF8:*']
        private_certificate_configuration_template_prototype_model_json['server_flag'] = True
        private_certificate_configuration_template_prototype_model_json['client_flag'] = True
        private_certificate_configuration_template_prototype_model_json['code_signing_flag'] = True
        private_certificate_configuration_template_prototype_model_json['email_protection_flag'] = True
        private_certificate_configuration_template_prototype_model_json['key_type'] = 'rsa'
        private_certificate_configuration_template_prototype_model_json['key_bits'] = 4096
        private_certificate_configuration_template_prototype_model_json['key_usage'] = ['DigitalSignature',
                                                                                        'KeyAgreement',
                                                                                        'KeyEncipherment']
        private_certificate_configuration_template_prototype_model_json['ext_key_usage'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['ext_key_usage_oids'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['use_csr_common_name'] = True
        private_certificate_configuration_template_prototype_model_json['use_csr_sans'] = True
        private_certificate_configuration_template_prototype_model_json['ou'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['organization'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['country'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['locality'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['province'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['street_address'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['postal_code'] = ['testString']
        private_certificate_configuration_template_prototype_model_json[
            'serial_number'] = 'd9:be:fe:35:ba:09:42:b5:35:ba:09:42:b5'
        private_certificate_configuration_template_prototype_model_json['require_cn'] = True
        private_certificate_configuration_template_prototype_model_json['policy_identifiers'] = ['testString']
        private_certificate_configuration_template_prototype_model_json['basic_constraints_valid_for_non_ca'] = True
        private_certificate_configuration_template_prototype_model_json['not_before_duration'] = '30s'

        # Construct a model instance of PrivateCertificateConfigurationTemplatePrototype by calling from_dict on the json representation
        private_certificate_configuration_template_prototype_model = PrivateCertificateConfigurationTemplatePrototype.from_dict(
            private_certificate_configuration_template_prototype_model_json)
        assert private_certificate_configuration_template_prototype_model != False

        # Construct a model instance of PrivateCertificateConfigurationTemplatePrototype by calling from_dict on the json representation
        private_certificate_configuration_template_prototype_model_dict = PrivateCertificateConfigurationTemplatePrototype.from_dict(
            private_certificate_configuration_template_prototype_model_json).__dict__
        private_certificate_configuration_template_prototype_model2 = PrivateCertificateConfigurationTemplatePrototype(
            **private_certificate_configuration_template_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_configuration_template_prototype_model == private_certificate_configuration_template_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_configuration_template_prototype_model_json2 = private_certificate_configuration_template_prototype_model.to_dict()
        assert private_certificate_configuration_template_prototype_model_json2 == private_certificate_configuration_template_prototype_model_json


class TestModel_PrivateCertificateCryptoProviderHPCS:
    """
    Test Class for PrivateCertificateCryptoProviderHPCS
    """

    def test_private_certificate_crypto_provider_hpcs_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateCryptoProviderHPCS
        """

        # Construct a json representation of a PrivateCertificateCryptoProviderHPCS model
        private_certificate_crypto_provider_hpcs_model_json = {}
        private_certificate_crypto_provider_hpcs_model_json['type'] = 'hyper_protect_crypto_services'
        private_certificate_crypto_provider_hpcs_model_json[
            'instance_crn'] = 'crn:v1:bluemix:public:hs-crypto:us-south:a/791f3fb10486421e97aa8512f18b7e65:b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5::'
        private_certificate_crypto_provider_hpcs_model_json[
            'pin_iam_credentials_secret_id'] = '6ebb80d3-26d1-4e24-81d6-afb0d8e22f54'
        private_certificate_crypto_provider_hpcs_model_json[
            'private_keystore_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'

        # Construct a model instance of PrivateCertificateCryptoProviderHPCS by calling from_dict on the json representation
        private_certificate_crypto_provider_hpcs_model = PrivateCertificateCryptoProviderHPCS.from_dict(
            private_certificate_crypto_provider_hpcs_model_json)
        assert private_certificate_crypto_provider_hpcs_model != False

        # Construct a model instance of PrivateCertificateCryptoProviderHPCS by calling from_dict on the json representation
        private_certificate_crypto_provider_hpcs_model_dict = PrivateCertificateCryptoProviderHPCS.from_dict(
            private_certificate_crypto_provider_hpcs_model_json).__dict__
        private_certificate_crypto_provider_hpcs_model2 = PrivateCertificateCryptoProviderHPCS(
            **private_certificate_crypto_provider_hpcs_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_crypto_provider_hpcs_model == private_certificate_crypto_provider_hpcs_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_crypto_provider_hpcs_model_json2 = private_certificate_crypto_provider_hpcs_model.to_dict()
        assert private_certificate_crypto_provider_hpcs_model_json2 == private_certificate_crypto_provider_hpcs_model_json


class TestModel_PrivateCertificateMetadata:
    """
    Test Class for PrivateCertificateMetadata
    """

    def test_private_certificate_metadata_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PrivateCertificateMetadata model
        private_certificate_metadata_model_json = {}
        private_certificate_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_metadata_model_json['crn'] = 'testString'
        private_certificate_metadata_model_json['custom_metadata'] = {'key': 'value'}
        private_certificate_metadata_model_json['description'] = 'Extended description for this secret.'
        private_certificate_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_metadata_model_json['labels'] = ['my-label']
        private_certificate_metadata_model_json['secret_group_id'] = 'default'
        private_certificate_metadata_model_json['secret_type'] = 'private_cert'
        private_certificate_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_metadata_model_json['versions_total'] = 0
        private_certificate_metadata_model_json['signing_algorithm'] = 'SHA256-RSA'
        private_certificate_metadata_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_metadata_model_json['certificate_template'] = 'cert-template-1'
        private_certificate_metadata_model_json['common_name'] = 'localhost'
        private_certificate_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_metadata_model_json['issuer'] = 'Lets Encrypt'
        private_certificate_metadata_model_json['rotation'] = rotation_policy_model
        private_certificate_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_metadata_model_json['validity'] = certificate_validity_model

        # Construct a model instance of PrivateCertificateMetadata by calling from_dict on the json representation
        private_certificate_metadata_model = PrivateCertificateMetadata.from_dict(
            private_certificate_metadata_model_json)
        assert private_certificate_metadata_model != False

        # Construct a model instance of PrivateCertificateMetadata by calling from_dict on the json representation
        private_certificate_metadata_model_dict = PrivateCertificateMetadata.from_dict(
            private_certificate_metadata_model_json).__dict__
        private_certificate_metadata_model2 = PrivateCertificateMetadata(**private_certificate_metadata_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_metadata_model == private_certificate_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_metadata_model_json2 = private_certificate_metadata_model.to_dict()
        assert private_certificate_metadata_model_json2 == private_certificate_metadata_model_json


class TestModel_PrivateCertificateMetadataPatch:
    """
    Test Class for PrivateCertificateMetadataPatch
    """

    def test_private_certificate_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PrivateCertificateMetadataPatch model
        private_certificate_metadata_patch_model_json = {}
        private_certificate_metadata_patch_model_json['name'] = 'my-secret-example'
        private_certificate_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        private_certificate_metadata_patch_model_json['labels'] = ['my-label']
        private_certificate_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        private_certificate_metadata_patch_model_json['rotation'] = rotation_policy_model

        # Construct a model instance of PrivateCertificateMetadataPatch by calling from_dict on the json representation
        private_certificate_metadata_patch_model = PrivateCertificateMetadataPatch.from_dict(
            private_certificate_metadata_patch_model_json)
        assert private_certificate_metadata_patch_model != False

        # Construct a model instance of PrivateCertificateMetadataPatch by calling from_dict on the json representation
        private_certificate_metadata_patch_model_dict = PrivateCertificateMetadataPatch.from_dict(
            private_certificate_metadata_patch_model_json).__dict__
        private_certificate_metadata_patch_model2 = PrivateCertificateMetadataPatch(
            **private_certificate_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_metadata_patch_model == private_certificate_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_metadata_patch_model_json2 = private_certificate_metadata_patch_model.to_dict()
        assert private_certificate_metadata_patch_model_json2 == private_certificate_metadata_patch_model_json


class TestModel_PrivateCertificatePrototype:
    """
    Test Class for PrivateCertificatePrototype
    """

    def test_private_certificate_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificatePrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PrivateCertificatePrototype model
        private_certificate_prototype_model_json = {}
        private_certificate_prototype_model_json['secret_type'] = 'private_cert'
        private_certificate_prototype_model_json['name'] = 'my-secret-example'
        private_certificate_prototype_model_json['description'] = 'Extended description for this secret.'
        private_certificate_prototype_model_json['secret_group_id'] = 'default'
        private_certificate_prototype_model_json['labels'] = ['my-label']
        private_certificate_prototype_model_json['certificate_template'] = 'cert-template-1'
        private_certificate_prototype_model_json['common_name'] = 'localhost'
        private_certificate_prototype_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        private_certificate_prototype_model_json['ip_sans'] = '1.1.1.1, 2.2.2.2'
        private_certificate_prototype_model_json['uri_sans'] = 'testString'
        private_certificate_prototype_model_json['other_sans'] = ['2.5.4.5;UTF8:*.example.com']
        private_certificate_prototype_model_json['csr'] = 'testString'
        private_certificate_prototype_model_json['format'] = 'pem'
        private_certificate_prototype_model_json['private_key_format'] = 'der'
        private_certificate_prototype_model_json['exclude_cn_from_sans'] = True
        private_certificate_prototype_model_json['ttl'] = '12h'
        private_certificate_prototype_model_json['rotation'] = rotation_policy_model
        private_certificate_prototype_model_json['custom_metadata'] = {'key': 'value'}
        private_certificate_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of PrivateCertificatePrototype by calling from_dict on the json representation
        private_certificate_prototype_model = PrivateCertificatePrototype.from_dict(
            private_certificate_prototype_model_json)
        assert private_certificate_prototype_model != False

        # Construct a model instance of PrivateCertificatePrototype by calling from_dict on the json representation
        private_certificate_prototype_model_dict = PrivateCertificatePrototype.from_dict(
            private_certificate_prototype_model_json).__dict__
        private_certificate_prototype_model2 = PrivateCertificatePrototype(**private_certificate_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_prototype_model == private_certificate_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_prototype_model_json2 = private_certificate_prototype_model.to_dict()
        assert private_certificate_prototype_model_json2 == private_certificate_prototype_model_json


class TestModel_PrivateCertificateVersion:
    """
    Test Class for PrivateCertificateVersion
    """

    def test_private_certificate_version_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PrivateCertificateVersion model
        private_certificate_version_model_json = {}
        private_certificate_version_model_json['auto_rotated'] = True
        private_certificate_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_version_model_json['secret_type'] = 'private_cert'
        private_certificate_version_model_json['secret_group_id'] = 'default'
        private_certificate_version_model_json['payload_available'] = True
        private_certificate_version_model_json['alias'] = 'current'
        private_certificate_version_model_json['version_custom_metadata'] = {'key': 'value'}
        private_certificate_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_version_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_version_model_json['validity'] = certificate_validity_model
        private_certificate_version_model_json['certificate'] = 'testString'
        private_certificate_version_model_json['private_key'] = 'testString'

        # Construct a model instance of PrivateCertificateVersion by calling from_dict on the json representation
        private_certificate_version_model = PrivateCertificateVersion.from_dict(private_certificate_version_model_json)
        assert private_certificate_version_model != False

        # Construct a model instance of PrivateCertificateVersion by calling from_dict on the json representation
        private_certificate_version_model_dict = PrivateCertificateVersion.from_dict(
            private_certificate_version_model_json).__dict__
        private_certificate_version_model2 = PrivateCertificateVersion(**private_certificate_version_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_version_model == private_certificate_version_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_version_model_json2 = private_certificate_version_model.to_dict()
        assert private_certificate_version_model_json2 == private_certificate_version_model_json


class TestModel_PrivateCertificateVersionActionRevoke:
    """
    Test Class for PrivateCertificateVersionActionRevoke
    """

    def test_private_certificate_version_action_revoke_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateVersionActionRevoke
        """

        # Construct a json representation of a PrivateCertificateVersionActionRevoke model
        private_certificate_version_action_revoke_model_json = {}
        private_certificate_version_action_revoke_model_json['action_type'] = 'private_cert_action_revoke_certificate'

        # Construct a model instance of PrivateCertificateVersionActionRevoke by calling from_dict on the json representation
        private_certificate_version_action_revoke_model = PrivateCertificateVersionActionRevoke.from_dict(
            private_certificate_version_action_revoke_model_json)
        assert private_certificate_version_action_revoke_model != False

        # Construct a model instance of PrivateCertificateVersionActionRevoke by calling from_dict on the json representation
        private_certificate_version_action_revoke_model_dict = PrivateCertificateVersionActionRevoke.from_dict(
            private_certificate_version_action_revoke_model_json).__dict__
        private_certificate_version_action_revoke_model2 = PrivateCertificateVersionActionRevoke(
            **private_certificate_version_action_revoke_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_version_action_revoke_model == private_certificate_version_action_revoke_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_version_action_revoke_model_json2 = private_certificate_version_action_revoke_model.to_dict()
        assert private_certificate_version_action_revoke_model_json2 == private_certificate_version_action_revoke_model_json


class TestModel_PrivateCertificateVersionActionRevokePrototype:
    """
    Test Class for PrivateCertificateVersionActionRevokePrototype
    """

    def test_private_certificate_version_action_revoke_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateVersionActionRevokePrototype
        """

        # Construct a json representation of a PrivateCertificateVersionActionRevokePrototype model
        private_certificate_version_action_revoke_prototype_model_json = {}
        private_certificate_version_action_revoke_prototype_model_json[
            'action_type'] = 'private_cert_action_revoke_certificate'

        # Construct a model instance of PrivateCertificateVersionActionRevokePrototype by calling from_dict on the json representation
        private_certificate_version_action_revoke_prototype_model = PrivateCertificateVersionActionRevokePrototype.from_dict(
            private_certificate_version_action_revoke_prototype_model_json)
        assert private_certificate_version_action_revoke_prototype_model != False

        # Construct a model instance of PrivateCertificateVersionActionRevokePrototype by calling from_dict on the json representation
        private_certificate_version_action_revoke_prototype_model_dict = PrivateCertificateVersionActionRevokePrototype.from_dict(
            private_certificate_version_action_revoke_prototype_model_json).__dict__
        private_certificate_version_action_revoke_prototype_model2 = PrivateCertificateVersionActionRevokePrototype(
            **private_certificate_version_action_revoke_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_version_action_revoke_prototype_model == private_certificate_version_action_revoke_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_version_action_revoke_prototype_model_json2 = private_certificate_version_action_revoke_prototype_model.to_dict()
        assert private_certificate_version_action_revoke_prototype_model_json2 == private_certificate_version_action_revoke_prototype_model_json


class TestModel_PrivateCertificateVersionMetadata:
    """
    Test Class for PrivateCertificateVersionMetadata
    """

    def test_private_certificate_version_metadata_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PrivateCertificateVersionMetadata model
        private_certificate_version_metadata_model_json = {}
        private_certificate_version_metadata_model_json['auto_rotated'] = True
        private_certificate_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        private_certificate_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        private_certificate_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_version_metadata_model_json['secret_type'] = 'private_cert'
        private_certificate_version_metadata_model_json['secret_group_id'] = 'default'
        private_certificate_version_metadata_model_json['payload_available'] = True
        private_certificate_version_metadata_model_json['alias'] = 'current'
        private_certificate_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        private_certificate_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        private_certificate_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        private_certificate_version_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        private_certificate_version_metadata_model_json['validity'] = certificate_validity_model

        # Construct a model instance of PrivateCertificateVersionMetadata by calling from_dict on the json representation
        private_certificate_version_metadata_model = PrivateCertificateVersionMetadata.from_dict(
            private_certificate_version_metadata_model_json)
        assert private_certificate_version_metadata_model != False

        # Construct a model instance of PrivateCertificateVersionMetadata by calling from_dict on the json representation
        private_certificate_version_metadata_model_dict = PrivateCertificateVersionMetadata.from_dict(
            private_certificate_version_metadata_model_json).__dict__
        private_certificate_version_metadata_model2 = PrivateCertificateVersionMetadata(
            **private_certificate_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_version_metadata_model == private_certificate_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_version_metadata_model_json2 = private_certificate_version_metadata_model.to_dict()
        assert private_certificate_version_metadata_model_json2 == private_certificate_version_metadata_model_json


class TestModel_PrivateCertificateVersionPrototype:
    """
    Test Class for PrivateCertificateVersionPrototype
    """

    def test_private_certificate_version_prototype_serialization(self):
        """
        Test serialization/deserialization for PrivateCertificateVersionPrototype
        """

        # Construct a json representation of a PrivateCertificateVersionPrototype model
        private_certificate_version_prototype_model_json = {}
        private_certificate_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        private_certificate_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}
        private_certificate_version_prototype_model_json['csr'] = 'testString'

        # Construct a model instance of PrivateCertificateVersionPrototype by calling from_dict on the json representation
        private_certificate_version_prototype_model = PrivateCertificateVersionPrototype.from_dict(
            private_certificate_version_prototype_model_json)
        assert private_certificate_version_prototype_model != False

        # Construct a model instance of PrivateCertificateVersionPrototype by calling from_dict on the json representation
        private_certificate_version_prototype_model_dict = PrivateCertificateVersionPrototype.from_dict(
            private_certificate_version_prototype_model_json).__dict__
        private_certificate_version_prototype_model2 = PrivateCertificateVersionPrototype(
            **private_certificate_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert private_certificate_version_prototype_model == private_certificate_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        private_certificate_version_prototype_model_json2 = private_certificate_version_prototype_model.to_dict()
        assert private_certificate_version_prototype_model_json2 == private_certificate_version_prototype_model_json


class TestModel_PublicCertificate:
    """
    Test Class for PublicCertificate
    """

    def test_public_certificate_serialization(self):
        """
        Test serialization/deserialization for PublicCertificate
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PublicCertificate model
        public_certificate_model_json = {}
        public_certificate_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_model_json['crn'] = 'testString'
        public_certificate_model_json['custom_metadata'] = {'key': 'value'}
        public_certificate_model_json['description'] = 'Extended description for this secret.'
        public_certificate_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_model_json['labels'] = ['my-label']
        public_certificate_model_json['secret_group_id'] = 'default'
        public_certificate_model_json['secret_type'] = 'public_cert'
        public_certificate_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_model_json['versions_total'] = 0
        public_certificate_model_json['signing_algorithm'] = 'SHA256-RSA'
        public_certificate_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        public_certificate_model_json['common_name'] = 'example.com'
        public_certificate_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        public_certificate_model_json['issuer'] = 'Lets Encrypt'
        public_certificate_model_json['key_algorithm'] = 'RSA2048'
        public_certificate_model_json['serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        public_certificate_model_json['validity'] = certificate_validity_model
        public_certificate_model_json['rotation'] = rotation_policy_model
        public_certificate_model_json['certificate'] = 'testString'
        public_certificate_model_json['intermediate'] = 'testString'
        public_certificate_model_json['private_key'] = 'testString'

        # Construct a model instance of PublicCertificate by calling from_dict on the json representation
        public_certificate_model = PublicCertificate.from_dict(public_certificate_model_json)
        assert public_certificate_model != False

        # Construct a model instance of PublicCertificate by calling from_dict on the json representation
        public_certificate_model_dict = PublicCertificate.from_dict(public_certificate_model_json).__dict__
        public_certificate_model2 = PublicCertificate(**public_certificate_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_model == public_certificate_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_model_json2 = public_certificate_model.to_dict()
        assert public_certificate_model_json2 == public_certificate_model_json


class TestModel_PublicCertificateActionValidateManualDNS:
    """
    Test Class for PublicCertificateActionValidateManualDNS
    """

    def test_public_certificate_action_validate_manual_dns_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateActionValidateManualDNS
        """

        # Construct a json representation of a PublicCertificateActionValidateManualDNS model
        public_certificate_action_validate_manual_dns_model_json = {}
        public_certificate_action_validate_manual_dns_model_json[
            'action_type'] = 'public_cert_action_validate_dns_challenge'

        # Construct a model instance of PublicCertificateActionValidateManualDNS by calling from_dict on the json representation
        public_certificate_action_validate_manual_dns_model = PublicCertificateActionValidateManualDNS.from_dict(
            public_certificate_action_validate_manual_dns_model_json)
        assert public_certificate_action_validate_manual_dns_model != False

        # Construct a model instance of PublicCertificateActionValidateManualDNS by calling from_dict on the json representation
        public_certificate_action_validate_manual_dns_model_dict = PublicCertificateActionValidateManualDNS.from_dict(
            public_certificate_action_validate_manual_dns_model_json).__dict__
        public_certificate_action_validate_manual_dns_model2 = PublicCertificateActionValidateManualDNS(
            **public_certificate_action_validate_manual_dns_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_action_validate_manual_dns_model == public_certificate_action_validate_manual_dns_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_action_validate_manual_dns_model_json2 = public_certificate_action_validate_manual_dns_model.to_dict()
        assert public_certificate_action_validate_manual_dns_model_json2 == public_certificate_action_validate_manual_dns_model_json


class TestModel_PublicCertificateActionValidateManualDNSPrototype:
    """
    Test Class for PublicCertificateActionValidateManualDNSPrototype
    """

    def test_public_certificate_action_validate_manual_dns_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateActionValidateManualDNSPrototype
        """

        # Construct a json representation of a PublicCertificateActionValidateManualDNSPrototype model
        public_certificate_action_validate_manual_dns_prototype_model_json = {}
        public_certificate_action_validate_manual_dns_prototype_model_json[
            'action_type'] = 'public_cert_action_validate_dns_challenge'

        # Construct a model instance of PublicCertificateActionValidateManualDNSPrototype by calling from_dict on the json representation
        public_certificate_action_validate_manual_dns_prototype_model = PublicCertificateActionValidateManualDNSPrototype.from_dict(
            public_certificate_action_validate_manual_dns_prototype_model_json)
        assert public_certificate_action_validate_manual_dns_prototype_model != False

        # Construct a model instance of PublicCertificateActionValidateManualDNSPrototype by calling from_dict on the json representation
        public_certificate_action_validate_manual_dns_prototype_model_dict = PublicCertificateActionValidateManualDNSPrototype.from_dict(
            public_certificate_action_validate_manual_dns_prototype_model_json).__dict__
        public_certificate_action_validate_manual_dns_prototype_model2 = PublicCertificateActionValidateManualDNSPrototype(
            **public_certificate_action_validate_manual_dns_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_action_validate_manual_dns_prototype_model == public_certificate_action_validate_manual_dns_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_action_validate_manual_dns_prototype_model_json2 = public_certificate_action_validate_manual_dns_prototype_model.to_dict()
        assert public_certificate_action_validate_manual_dns_prototype_model_json2 == public_certificate_action_validate_manual_dns_prototype_model_json


class TestModel_PublicCertificateConfigurationCALetsEncrypt:
    """
    Test Class for PublicCertificateConfigurationCALetsEncrypt
    """

    def test_public_certificate_configuration_ca_lets_encrypt_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationCALetsEncrypt
        """

        # Construct a json representation of a PublicCertificateConfigurationCALetsEncrypt model
        public_certificate_configuration_ca_lets_encrypt_model_json = {}
        public_certificate_configuration_ca_lets_encrypt_model_json[
            'config_type'] = 'public_cert_configuration_ca_lets_encrypt'
        public_certificate_configuration_ca_lets_encrypt_model_json['name'] = 'my-secret-engine-config'
        public_certificate_configuration_ca_lets_encrypt_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_ca_lets_encrypt_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_ca_lets_encrypt_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_ca_lets_encrypt_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_ca_lets_encrypt_model_json['lets_encrypt_environment'] = 'production'
        public_certificate_configuration_ca_lets_encrypt_model_json['lets_encrypt_preferred_chain'] = 'testString'
        public_certificate_configuration_ca_lets_encrypt_model_json['lets_encrypt_private_key'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationCALetsEncrypt by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_model = PublicCertificateConfigurationCALetsEncrypt.from_dict(
            public_certificate_configuration_ca_lets_encrypt_model_json)
        assert public_certificate_configuration_ca_lets_encrypt_model != False

        # Construct a model instance of PublicCertificateConfigurationCALetsEncrypt by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_model_dict = PublicCertificateConfigurationCALetsEncrypt.from_dict(
            public_certificate_configuration_ca_lets_encrypt_model_json).__dict__
        public_certificate_configuration_ca_lets_encrypt_model2 = PublicCertificateConfigurationCALetsEncrypt(
            **public_certificate_configuration_ca_lets_encrypt_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_ca_lets_encrypt_model == public_certificate_configuration_ca_lets_encrypt_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_ca_lets_encrypt_model_json2 = public_certificate_configuration_ca_lets_encrypt_model.to_dict()
        assert public_certificate_configuration_ca_lets_encrypt_model_json2 == public_certificate_configuration_ca_lets_encrypt_model_json


class TestModel_PublicCertificateConfigurationCALetsEncryptMetadata:
    """
    Test Class for PublicCertificateConfigurationCALetsEncryptMetadata
    """

    def test_public_certificate_configuration_ca_lets_encrypt_metadata_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationCALetsEncryptMetadata
        """

        # Construct a json representation of a PublicCertificateConfigurationCALetsEncryptMetadata model
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json = {}
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json[
            'config_type'] = 'public_cert_configuration_ca_lets_encrypt'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json['name'] = 'my-secret-engine-config'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json['lets_encrypt_environment'] = 'production'
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json[
            'lets_encrypt_preferred_chain'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptMetadata by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_metadata_model = PublicCertificateConfigurationCALetsEncryptMetadata.from_dict(
            public_certificate_configuration_ca_lets_encrypt_metadata_model_json)
        assert public_certificate_configuration_ca_lets_encrypt_metadata_model != False

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptMetadata by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_metadata_model_dict = PublicCertificateConfigurationCALetsEncryptMetadata.from_dict(
            public_certificate_configuration_ca_lets_encrypt_metadata_model_json).__dict__
        public_certificate_configuration_ca_lets_encrypt_metadata_model2 = PublicCertificateConfigurationCALetsEncryptMetadata(
            **public_certificate_configuration_ca_lets_encrypt_metadata_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_ca_lets_encrypt_metadata_model == public_certificate_configuration_ca_lets_encrypt_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_ca_lets_encrypt_metadata_model_json2 = public_certificate_configuration_ca_lets_encrypt_metadata_model.to_dict()
        assert public_certificate_configuration_ca_lets_encrypt_metadata_model_json2 == public_certificate_configuration_ca_lets_encrypt_metadata_model_json


class TestModel_PublicCertificateConfigurationCALetsEncryptPatch:
    """
    Test Class for PublicCertificateConfigurationCALetsEncryptPatch
    """

    def test_public_certificate_configuration_ca_lets_encrypt_patch_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationCALetsEncryptPatch
        """

        # Construct a json representation of a PublicCertificateConfigurationCALetsEncryptPatch model
        public_certificate_configuration_ca_lets_encrypt_patch_model_json = {}
        public_certificate_configuration_ca_lets_encrypt_patch_model_json['lets_encrypt_environment'] = 'production'
        public_certificate_configuration_ca_lets_encrypt_patch_model_json['lets_encrypt_private_key'] = 'testString'
        public_certificate_configuration_ca_lets_encrypt_patch_model_json['lets_encrypt_preferred_chain'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptPatch by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_patch_model = PublicCertificateConfigurationCALetsEncryptPatch.from_dict(
            public_certificate_configuration_ca_lets_encrypt_patch_model_json)
        assert public_certificate_configuration_ca_lets_encrypt_patch_model != False

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptPatch by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_patch_model_dict = PublicCertificateConfigurationCALetsEncryptPatch.from_dict(
            public_certificate_configuration_ca_lets_encrypt_patch_model_json).__dict__
        public_certificate_configuration_ca_lets_encrypt_patch_model2 = PublicCertificateConfigurationCALetsEncryptPatch(
            **public_certificate_configuration_ca_lets_encrypt_patch_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_ca_lets_encrypt_patch_model == public_certificate_configuration_ca_lets_encrypt_patch_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_ca_lets_encrypt_patch_model_json2 = public_certificate_configuration_ca_lets_encrypt_patch_model.to_dict()
        assert public_certificate_configuration_ca_lets_encrypt_patch_model_json2 == public_certificate_configuration_ca_lets_encrypt_patch_model_json


class TestModel_PublicCertificateConfigurationCALetsEncryptPrototype:
    """
    Test Class for PublicCertificateConfigurationCALetsEncryptPrototype
    """

    def test_public_certificate_configuration_ca_lets_encrypt_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationCALetsEncryptPrototype
        """

        # Construct a json representation of a PublicCertificateConfigurationCALetsEncryptPrototype model
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json = {}
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json[
            'config_type'] = 'public_cert_configuration_ca_lets_encrypt'
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json['name'] = 'my-example-engine-config'
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json['lets_encrypt_environment'] = 'production'
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json['lets_encrypt_private_key'] = 'testString'
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json[
            'lets_encrypt_preferred_chain'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptPrototype by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_prototype_model = PublicCertificateConfigurationCALetsEncryptPrototype.from_dict(
            public_certificate_configuration_ca_lets_encrypt_prototype_model_json)
        assert public_certificate_configuration_ca_lets_encrypt_prototype_model != False

        # Construct a model instance of PublicCertificateConfigurationCALetsEncryptPrototype by calling from_dict on the json representation
        public_certificate_configuration_ca_lets_encrypt_prototype_model_dict = PublicCertificateConfigurationCALetsEncryptPrototype.from_dict(
            public_certificate_configuration_ca_lets_encrypt_prototype_model_json).__dict__
        public_certificate_configuration_ca_lets_encrypt_prototype_model2 = PublicCertificateConfigurationCALetsEncryptPrototype(
            **public_certificate_configuration_ca_lets_encrypt_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_ca_lets_encrypt_prototype_model == public_certificate_configuration_ca_lets_encrypt_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_ca_lets_encrypt_prototype_model_json2 = public_certificate_configuration_ca_lets_encrypt_prototype_model.to_dict()
        assert public_certificate_configuration_ca_lets_encrypt_prototype_model_json2 == public_certificate_configuration_ca_lets_encrypt_prototype_model_json


class TestModel_PublicCertificateConfigurationDNSClassicInfrastructure:
    """
    Test Class for PublicCertificateConfigurationDNSClassicInfrastructure
    """

    def test_public_certificate_configuration_dns_classic_infrastructure_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSClassicInfrastructure
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSClassicInfrastructure model
        public_certificate_configuration_dns_classic_infrastructure_model_json = {}
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'config_type'] = 'public_cert_configuration_dns_classic_infrastructure'
        public_certificate_configuration_dns_classic_infrastructure_model_json['name'] = 'my-secret-engine-config'
        public_certificate_configuration_dns_classic_infrastructure_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'classic_infrastructure_username'] = 'testString'
        public_certificate_configuration_dns_classic_infrastructure_model_json[
            'classic_infrastructure_password'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructure by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_model = PublicCertificateConfigurationDNSClassicInfrastructure.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_model_json)
        assert public_certificate_configuration_dns_classic_infrastructure_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructure by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_model_dict = PublicCertificateConfigurationDNSClassicInfrastructure.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_model_json).__dict__
        public_certificate_configuration_dns_classic_infrastructure_model2 = PublicCertificateConfigurationDNSClassicInfrastructure(
            **public_certificate_configuration_dns_classic_infrastructure_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_classic_infrastructure_model == public_certificate_configuration_dns_classic_infrastructure_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_classic_infrastructure_model_json2 = public_certificate_configuration_dns_classic_infrastructure_model.to_dict()
        assert public_certificate_configuration_dns_classic_infrastructure_model_json2 == public_certificate_configuration_dns_classic_infrastructure_model_json


class TestModel_PublicCertificateConfigurationDNSClassicInfrastructureMetadata:
    """
    Test Class for PublicCertificateConfigurationDNSClassicInfrastructureMetadata
    """

    def test_public_certificate_configuration_dns_classic_infrastructure_metadata_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSClassicInfrastructureMetadata
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSClassicInfrastructureMetadata model
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json = {}
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json[
            'config_type'] = 'public_cert_configuration_dns_classic_infrastructure'
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json[
            'name'] = 'my-secret-engine-config'
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructureMetadata by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_metadata_model = PublicCertificateConfigurationDNSClassicInfrastructureMetadata.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_metadata_model_json)
        assert public_certificate_configuration_dns_classic_infrastructure_metadata_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructureMetadata by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_dict = PublicCertificateConfigurationDNSClassicInfrastructureMetadata.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_metadata_model_json).__dict__
        public_certificate_configuration_dns_classic_infrastructure_metadata_model2 = PublicCertificateConfigurationDNSClassicInfrastructureMetadata(
            **public_certificate_configuration_dns_classic_infrastructure_metadata_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_classic_infrastructure_metadata_model == public_certificate_configuration_dns_classic_infrastructure_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_classic_infrastructure_metadata_model_json2 = public_certificate_configuration_dns_classic_infrastructure_metadata_model.to_dict()
        assert public_certificate_configuration_dns_classic_infrastructure_metadata_model_json2 == public_certificate_configuration_dns_classic_infrastructure_metadata_model_json


class TestModel_PublicCertificateConfigurationDNSClassicInfrastructurePatch:
    """
    Test Class for PublicCertificateConfigurationDNSClassicInfrastructurePatch
    """

    def test_public_certificate_configuration_dns_classic_infrastructure_patch_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSClassicInfrastructurePatch
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSClassicInfrastructurePatch model
        public_certificate_configuration_dns_classic_infrastructure_patch_model_json = {}
        public_certificate_configuration_dns_classic_infrastructure_patch_model_json[
            'classic_infrastructure_username'] = 'testString'
        public_certificate_configuration_dns_classic_infrastructure_patch_model_json[
            'classic_infrastructure_password'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructurePatch by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_patch_model = PublicCertificateConfigurationDNSClassicInfrastructurePatch.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_patch_model_json)
        assert public_certificate_configuration_dns_classic_infrastructure_patch_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructurePatch by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_patch_model_dict = PublicCertificateConfigurationDNSClassicInfrastructurePatch.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_patch_model_json).__dict__
        public_certificate_configuration_dns_classic_infrastructure_patch_model2 = PublicCertificateConfigurationDNSClassicInfrastructurePatch(
            **public_certificate_configuration_dns_classic_infrastructure_patch_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_classic_infrastructure_patch_model == public_certificate_configuration_dns_classic_infrastructure_patch_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_classic_infrastructure_patch_model_json2 = public_certificate_configuration_dns_classic_infrastructure_patch_model.to_dict()
        assert public_certificate_configuration_dns_classic_infrastructure_patch_model_json2 == public_certificate_configuration_dns_classic_infrastructure_patch_model_json


class TestModel_PublicCertificateConfigurationDNSClassicInfrastructurePrototype:
    """
    Test Class for PublicCertificateConfigurationDNSClassicInfrastructurePrototype
    """

    def test_public_certificate_configuration_dns_classic_infrastructure_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSClassicInfrastructurePrototype
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSClassicInfrastructurePrototype model
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json = {}
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json[
            'config_type'] = 'public_cert_configuration_dns_classic_infrastructure'
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json[
            'name'] = 'my-example-engine-config'
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json[
            'classic_infrastructure_username'] = 'testString'
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json[
            'classic_infrastructure_password'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructurePrototype by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_prototype_model = PublicCertificateConfigurationDNSClassicInfrastructurePrototype.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_prototype_model_json)
        assert public_certificate_configuration_dns_classic_infrastructure_prototype_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSClassicInfrastructurePrototype by calling from_dict on the json representation
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_dict = PublicCertificateConfigurationDNSClassicInfrastructurePrototype.from_dict(
            public_certificate_configuration_dns_classic_infrastructure_prototype_model_json).__dict__
        public_certificate_configuration_dns_classic_infrastructure_prototype_model2 = PublicCertificateConfigurationDNSClassicInfrastructurePrototype(
            **public_certificate_configuration_dns_classic_infrastructure_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_classic_infrastructure_prototype_model == public_certificate_configuration_dns_classic_infrastructure_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_classic_infrastructure_prototype_model_json2 = public_certificate_configuration_dns_classic_infrastructure_prototype_model.to_dict()
        assert public_certificate_configuration_dns_classic_infrastructure_prototype_model_json2 == public_certificate_configuration_dns_classic_infrastructure_prototype_model_json


class TestModel_PublicCertificateConfigurationDNSCloudInternetServices:
    """
    Test Class for PublicCertificateConfigurationDNSCloudInternetServices
    """

    def test_public_certificate_configuration_dns_cloud_internet_services_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSCloudInternetServices
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSCloudInternetServices model
        public_certificate_configuration_dns_cloud_internet_services_model_json = {}
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'config_type'] = 'public_cert_configuration_dns_cloud_internet_services'
        public_certificate_configuration_dns_cloud_internet_services_model_json['name'] = 'my-secret-engine-config'
        public_certificate_configuration_dns_cloud_internet_services_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'cloud_internet_services_apikey'] = 'testString'
        public_certificate_configuration_dns_cloud_internet_services_model_json[
            'cloud_internet_services_crn'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServices by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_model = PublicCertificateConfigurationDNSCloudInternetServices.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_model_json)
        assert public_certificate_configuration_dns_cloud_internet_services_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServices by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_model_dict = PublicCertificateConfigurationDNSCloudInternetServices.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_model_json).__dict__
        public_certificate_configuration_dns_cloud_internet_services_model2 = PublicCertificateConfigurationDNSCloudInternetServices(
            **public_certificate_configuration_dns_cloud_internet_services_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_cloud_internet_services_model == public_certificate_configuration_dns_cloud_internet_services_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_cloud_internet_services_model_json2 = public_certificate_configuration_dns_cloud_internet_services_model.to_dict()
        assert public_certificate_configuration_dns_cloud_internet_services_model_json2 == public_certificate_configuration_dns_cloud_internet_services_model_json


class TestModel_PublicCertificateConfigurationDNSCloudInternetServicesMetadata:
    """
    Test Class for PublicCertificateConfigurationDNSCloudInternetServicesMetadata
    """

    def test_public_certificate_configuration_dns_cloud_internet_services_metadata_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSCloudInternetServicesMetadata
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSCloudInternetServicesMetadata model
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json = {}
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json[
            'config_type'] = 'public_cert_configuration_dns_cloud_internet_services'
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json[
            'name'] = 'my-secret-engine-config'
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json['secret_type'] = 'arbitrary'
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json[
            'created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json[
            'updated_at'] = '2022-04-12T23:20:50.520000Z'

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesMetadata by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_metadata_model = PublicCertificateConfigurationDNSCloudInternetServicesMetadata.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_metadata_model_json)
        assert public_certificate_configuration_dns_cloud_internet_services_metadata_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesMetadata by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_dict = PublicCertificateConfigurationDNSCloudInternetServicesMetadata.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_metadata_model_json).__dict__
        public_certificate_configuration_dns_cloud_internet_services_metadata_model2 = PublicCertificateConfigurationDNSCloudInternetServicesMetadata(
            **public_certificate_configuration_dns_cloud_internet_services_metadata_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_cloud_internet_services_metadata_model == public_certificate_configuration_dns_cloud_internet_services_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_cloud_internet_services_metadata_model_json2 = public_certificate_configuration_dns_cloud_internet_services_metadata_model.to_dict()
        assert public_certificate_configuration_dns_cloud_internet_services_metadata_model_json2 == public_certificate_configuration_dns_cloud_internet_services_metadata_model_json


class TestModel_PublicCertificateConfigurationDNSCloudInternetServicesPatch:
    """
    Test Class for PublicCertificateConfigurationDNSCloudInternetServicesPatch
    """

    def test_public_certificate_configuration_dns_cloud_internet_services_patch_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSCloudInternetServicesPatch
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSCloudInternetServicesPatch model
        public_certificate_configuration_dns_cloud_internet_services_patch_model_json = {}
        public_certificate_configuration_dns_cloud_internet_services_patch_model_json[
            'cloud_internet_services_apikey'] = 'testString'
        public_certificate_configuration_dns_cloud_internet_services_patch_model_json[
            'cloud_internet_services_crn'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesPatch by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_patch_model = PublicCertificateConfigurationDNSCloudInternetServicesPatch.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_patch_model_json)
        assert public_certificate_configuration_dns_cloud_internet_services_patch_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesPatch by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_patch_model_dict = PublicCertificateConfigurationDNSCloudInternetServicesPatch.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_patch_model_json).__dict__
        public_certificate_configuration_dns_cloud_internet_services_patch_model2 = PublicCertificateConfigurationDNSCloudInternetServicesPatch(
            **public_certificate_configuration_dns_cloud_internet_services_patch_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_cloud_internet_services_patch_model == public_certificate_configuration_dns_cloud_internet_services_patch_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_cloud_internet_services_patch_model_json2 = public_certificate_configuration_dns_cloud_internet_services_patch_model.to_dict()
        assert public_certificate_configuration_dns_cloud_internet_services_patch_model_json2 == public_certificate_configuration_dns_cloud_internet_services_patch_model_json


class TestModel_PublicCertificateConfigurationDNSCloudInternetServicesPrototype:
    """
    Test Class for PublicCertificateConfigurationDNSCloudInternetServicesPrototype
    """

    def test_public_certificate_configuration_dns_cloud_internet_services_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateConfigurationDNSCloudInternetServicesPrototype
        """

        # Construct a json representation of a PublicCertificateConfigurationDNSCloudInternetServicesPrototype model
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json = {}
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json[
            'config_type'] = 'public_cert_configuration_dns_cloud_internet_services'
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json[
            'name'] = 'my-example-engine-config'
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json[
            'cloud_internet_services_apikey'] = 'testString'
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json[
            'cloud_internet_services_crn'] = 'testString'

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesPrototype by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_prototype_model = PublicCertificateConfigurationDNSCloudInternetServicesPrototype.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_prototype_model_json)
        assert public_certificate_configuration_dns_cloud_internet_services_prototype_model != False

        # Construct a model instance of PublicCertificateConfigurationDNSCloudInternetServicesPrototype by calling from_dict on the json representation
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_dict = PublicCertificateConfigurationDNSCloudInternetServicesPrototype.from_dict(
            public_certificate_configuration_dns_cloud_internet_services_prototype_model_json).__dict__
        public_certificate_configuration_dns_cloud_internet_services_prototype_model2 = PublicCertificateConfigurationDNSCloudInternetServicesPrototype(
            **public_certificate_configuration_dns_cloud_internet_services_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_configuration_dns_cloud_internet_services_prototype_model == public_certificate_configuration_dns_cloud_internet_services_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_configuration_dns_cloud_internet_services_prototype_model_json2 = public_certificate_configuration_dns_cloud_internet_services_prototype_model.to_dict()
        assert public_certificate_configuration_dns_cloud_internet_services_prototype_model_json2 == public_certificate_configuration_dns_cloud_internet_services_prototype_model_json


class TestModel_PublicCertificateMetadata:
    """
    Test Class for PublicCertificateMetadata
    """

    def test_public_certificate_metadata_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PublicCertificateMetadata model
        public_certificate_metadata_model_json = {}
        public_certificate_metadata_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_metadata_model_json['crn'] = 'testString'
        public_certificate_metadata_model_json['custom_metadata'] = {'key': 'value'}
        public_certificate_metadata_model_json['description'] = 'Extended description for this secret.'
        public_certificate_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_metadata_model_json['labels'] = ['my-label']
        public_certificate_metadata_model_json['secret_group_id'] = 'default'
        public_certificate_metadata_model_json['secret_type'] = 'public_cert'
        public_certificate_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_metadata_model_json['versions_total'] = 0
        public_certificate_metadata_model_json['signing_algorithm'] = 'SHA256-RSA'
        public_certificate_metadata_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        public_certificate_metadata_model_json['common_name'] = 'example.com'
        public_certificate_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        public_certificate_metadata_model_json['issuer'] = 'Lets Encrypt'
        public_certificate_metadata_model_json['key_algorithm'] = 'RSA2048'
        public_certificate_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        public_certificate_metadata_model_json['validity'] = certificate_validity_model
        public_certificate_metadata_model_json['rotation'] = rotation_policy_model

        # Construct a model instance of PublicCertificateMetadata by calling from_dict on the json representation
        public_certificate_metadata_model = PublicCertificateMetadata.from_dict(public_certificate_metadata_model_json)
        assert public_certificate_metadata_model != False

        # Construct a model instance of PublicCertificateMetadata by calling from_dict on the json representation
        public_certificate_metadata_model_dict = PublicCertificateMetadata.from_dict(
            public_certificate_metadata_model_json).__dict__
        public_certificate_metadata_model2 = PublicCertificateMetadata(**public_certificate_metadata_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_metadata_model == public_certificate_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_metadata_model_json2 = public_certificate_metadata_model.to_dict()
        assert public_certificate_metadata_model_json2 == public_certificate_metadata_model_json


class TestModel_PublicCertificateMetadataPatch:
    """
    Test Class for PublicCertificateMetadataPatch
    """

    def test_public_certificate_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PublicCertificateMetadataPatch model
        public_certificate_metadata_patch_model_json = {}
        public_certificate_metadata_patch_model_json['name'] = 'my-secret-example'
        public_certificate_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        public_certificate_metadata_patch_model_json['labels'] = ['my-label']
        public_certificate_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        public_certificate_metadata_patch_model_json['rotation'] = rotation_policy_model

        # Construct a model instance of PublicCertificateMetadataPatch by calling from_dict on the json representation
        public_certificate_metadata_patch_model = PublicCertificateMetadataPatch.from_dict(
            public_certificate_metadata_patch_model_json)
        assert public_certificate_metadata_patch_model != False

        # Construct a model instance of PublicCertificateMetadataPatch by calling from_dict on the json representation
        public_certificate_metadata_patch_model_dict = PublicCertificateMetadataPatch.from_dict(
            public_certificate_metadata_patch_model_json).__dict__
        public_certificate_metadata_patch_model2 = PublicCertificateMetadataPatch(
            **public_certificate_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_metadata_patch_model == public_certificate_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_metadata_patch_model_json2 = public_certificate_metadata_patch_model.to_dict()
        assert public_certificate_metadata_patch_model_json2 == public_certificate_metadata_patch_model_json


class TestModel_PublicCertificatePrototype:
    """
    Test Class for PublicCertificatePrototype
    """

    def test_public_certificate_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificatePrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a PublicCertificatePrototype model
        public_certificate_prototype_model_json = {}
        public_certificate_prototype_model_json['secret_type'] = 'public_cert'
        public_certificate_prototype_model_json['name'] = 'my-secret-example'
        public_certificate_prototype_model_json['description'] = 'Extended description for this secret.'
        public_certificate_prototype_model_json['secret_group_id'] = 'default'
        public_certificate_prototype_model_json['labels'] = ['my-label']
        public_certificate_prototype_model_json['common_name'] = 'example.com'
        public_certificate_prototype_model_json['alt_names'] = ['s1.example.com', '*.s2.example.com']
        public_certificate_prototype_model_json['key_algorithm'] = 'RSA2048'
        public_certificate_prototype_model_json['ca'] = 'my-ca-config'
        public_certificate_prototype_model_json['dns'] = 'my-dns-config'
        public_certificate_prototype_model_json['bundle_certs'] = True
        public_certificate_prototype_model_json['rotation'] = rotation_policy_model
        public_certificate_prototype_model_json['custom_metadata'] = {'key': 'value'}
        public_certificate_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of PublicCertificatePrototype by calling from_dict on the json representation
        public_certificate_prototype_model = PublicCertificatePrototype.from_dict(
            public_certificate_prototype_model_json)
        assert public_certificate_prototype_model != False

        # Construct a model instance of PublicCertificatePrototype by calling from_dict on the json representation
        public_certificate_prototype_model_dict = PublicCertificatePrototype.from_dict(
            public_certificate_prototype_model_json).__dict__
        public_certificate_prototype_model2 = PublicCertificatePrototype(**public_certificate_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_prototype_model == public_certificate_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_prototype_model_json2 = public_certificate_prototype_model.to_dict()
        assert public_certificate_prototype_model_json2 == public_certificate_prototype_model_json


class TestModel_PublicCertificateRotationPolicy:
    """
    Test Class for PublicCertificateRotationPolicy
    """

    def test_public_certificate_rotation_policy_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateRotationPolicy
        """

        # Construct a json representation of a PublicCertificateRotationPolicy model
        public_certificate_rotation_policy_model_json = {}
        public_certificate_rotation_policy_model_json['auto_rotate'] = True
        public_certificate_rotation_policy_model_json['rotate_keys'] = True

        # Construct a model instance of PublicCertificateRotationPolicy by calling from_dict on the json representation
        public_certificate_rotation_policy_model = PublicCertificateRotationPolicy.from_dict(
            public_certificate_rotation_policy_model_json)
        assert public_certificate_rotation_policy_model != False

        # Construct a model instance of PublicCertificateRotationPolicy by calling from_dict on the json representation
        public_certificate_rotation_policy_model_dict = PublicCertificateRotationPolicy.from_dict(
            public_certificate_rotation_policy_model_json).__dict__
        public_certificate_rotation_policy_model2 = PublicCertificateRotationPolicy(
            **public_certificate_rotation_policy_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_rotation_policy_model == public_certificate_rotation_policy_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_rotation_policy_model_json2 = public_certificate_rotation_policy_model.to_dict()
        assert public_certificate_rotation_policy_model_json2 == public_certificate_rotation_policy_model_json


class TestModel_PublicCertificateVersion:
    """
    Test Class for PublicCertificateVersion
    """

    def test_public_certificate_version_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PublicCertificateVersion model
        public_certificate_version_model_json = {}
        public_certificate_version_model_json['auto_rotated'] = True
        public_certificate_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_version_model_json['secret_type'] = 'public_cert'
        public_certificate_version_model_json['secret_group_id'] = 'default'
        public_certificate_version_model_json['payload_available'] = True
        public_certificate_version_model_json['alias'] = 'current'
        public_certificate_version_model_json['version_custom_metadata'] = {'key': 'value'}
        public_certificate_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        public_certificate_version_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        public_certificate_version_model_json['validity'] = certificate_validity_model
        public_certificate_version_model_json['certificate'] = 'testString'
        public_certificate_version_model_json['intermediate'] = 'testString'
        public_certificate_version_model_json['private_key'] = 'testString'

        # Construct a model instance of PublicCertificateVersion by calling from_dict on the json representation
        public_certificate_version_model = PublicCertificateVersion.from_dict(public_certificate_version_model_json)
        assert public_certificate_version_model != False

        # Construct a model instance of PublicCertificateVersion by calling from_dict on the json representation
        public_certificate_version_model_dict = PublicCertificateVersion.from_dict(
            public_certificate_version_model_json).__dict__
        public_certificate_version_model2 = PublicCertificateVersion(**public_certificate_version_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_version_model == public_certificate_version_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_version_model_json2 = public_certificate_version_model.to_dict()
        assert public_certificate_version_model_json2 == public_certificate_version_model_json


class TestModel_PublicCertificateVersionMetadata:
    """
    Test Class for PublicCertificateVersionMetadata
    """

    def test_public_certificate_version_metadata_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {}  # CertificateValidity
        certificate_validity_model['not_before'] = '2025-04-12T23:20:50Z'
        certificate_validity_model['not_after'] = '2025-04-12T23:20:50Z'

        # Construct a json representation of a PublicCertificateVersionMetadata model
        public_certificate_version_metadata_model_json = {}
        public_certificate_version_metadata_model_json['auto_rotated'] = True
        public_certificate_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        public_certificate_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        public_certificate_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_version_metadata_model_json['secret_type'] = 'public_cert'
        public_certificate_version_metadata_model_json['secret_group_id'] = 'default'
        public_certificate_version_metadata_model_json['payload_available'] = True
        public_certificate_version_metadata_model_json['alias'] = 'current'
        public_certificate_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        public_certificate_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        public_certificate_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        public_certificate_version_metadata_model_json[
            'serial_number'] = '38:eb:01:a3:22:e9:de:55:24:56:9b:14:cb:e2:f3:e3:e2:fb:f5:18'
        public_certificate_version_metadata_model_json['validity'] = certificate_validity_model

        # Construct a model instance of PublicCertificateVersionMetadata by calling from_dict on the json representation
        public_certificate_version_metadata_model = PublicCertificateVersionMetadata.from_dict(
            public_certificate_version_metadata_model_json)
        assert public_certificate_version_metadata_model != False

        # Construct a model instance of PublicCertificateVersionMetadata by calling from_dict on the json representation
        public_certificate_version_metadata_model_dict = PublicCertificateVersionMetadata.from_dict(
            public_certificate_version_metadata_model_json).__dict__
        public_certificate_version_metadata_model2 = PublicCertificateVersionMetadata(
            **public_certificate_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_version_metadata_model == public_certificate_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_version_metadata_model_json2 = public_certificate_version_metadata_model.to_dict()
        assert public_certificate_version_metadata_model_json2 == public_certificate_version_metadata_model_json


class TestModel_PublicCertificateVersionPrototype:
    """
    Test Class for PublicCertificateVersionPrototype
    """

    def test_public_certificate_version_prototype_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateVersionPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        public_certificate_rotation_object_model = {}  # PublicCertificateRotationObject
        public_certificate_rotation_object_model['rotate_keys'] = True

        # Construct a json representation of a PublicCertificateVersionPrototype model
        public_certificate_version_prototype_model_json = {}
        public_certificate_version_prototype_model_json['rotation'] = public_certificate_rotation_object_model
        public_certificate_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        public_certificate_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of PublicCertificateVersionPrototype by calling from_dict on the json representation
        public_certificate_version_prototype_model = PublicCertificateVersionPrototype.from_dict(
            public_certificate_version_prototype_model_json)
        assert public_certificate_version_prototype_model != False

        # Construct a model instance of PublicCertificateVersionPrototype by calling from_dict on the json representation
        public_certificate_version_prototype_model_dict = PublicCertificateVersionPrototype.from_dict(
            public_certificate_version_prototype_model_json).__dict__
        public_certificate_version_prototype_model2 = PublicCertificateVersionPrototype(
            **public_certificate_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_version_prototype_model == public_certificate_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_version_prototype_model_json2 = public_certificate_version_prototype_model.to_dict()
        assert public_certificate_version_prototype_model_json2 == public_certificate_version_prototype_model_json


class TestModel_ServiceCredentialsSecret:
    """
    Test Class for ServiceCredentialsSecret
    """

    def test_service_credentials_secret_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        service_credentials_source_service_instance_model = {}  # ServiceCredentialsSourceServiceInstance
        service_credentials_source_service_instance_model['crn'] = 'testString'

        service_credentials_source_service_parameters_model = {}  # ServiceCredentialsSourceServiceParameters
        service_credentials_source_service_parameters_model['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model['foo'] = 'testString'

        service_credentials_source_service_role_model = {}  # ServiceCredentialsSourceServiceRole
        service_credentials_source_service_role_model['crn'] = 'testString'

        service_credentials_source_service_iam_apikey_model = {}  # ServiceCredentialsSourceServiceIamApikey

        service_credentials_source_service_iam_role_model = {}  # ServiceCredentialsSourceServiceIamRole

        service_credentials_source_service_iam_serviceid_model = {}  # ServiceCredentialsSourceServiceIamServiceid

        service_credentials_source_service_iam_model = {}  # ServiceCredentialsSourceServiceIam
        service_credentials_source_service_iam_model['apikey'] = service_credentials_source_service_iam_apikey_model
        service_credentials_source_service_iam_model['role'] = service_credentials_source_service_iam_role_model
        service_credentials_source_service_iam_model[
            'serviceid'] = service_credentials_source_service_iam_serviceid_model

        service_credentials_resource_key_model = {}  # ServiceCredentialsResourceKey

        service_credentials_secret_source_service_ro_model = {}  # ServiceCredentialsSecretSourceServiceRO
        service_credentials_secret_source_service_ro_model[
            'instance'] = service_credentials_source_service_instance_model
        service_credentials_secret_source_service_ro_model[
            'parameters'] = service_credentials_source_service_parameters_model
        service_credentials_secret_source_service_ro_model['role'] = service_credentials_source_service_role_model
        service_credentials_secret_source_service_ro_model['iam'] = service_credentials_source_service_iam_model
        service_credentials_secret_source_service_ro_model['resource_key'] = service_credentials_resource_key_model

        service_credentials_secret_credentials_model = {}  # ServiceCredentialsSecretCredentials
        service_credentials_secret_credentials_model['foo'] = 'testString'

        # Construct a json representation of a ServiceCredentialsSecret model
        service_credentials_secret_model_json = {}
        service_credentials_secret_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        service_credentials_secret_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_model_json['crn'] = 'testString'
        service_credentials_secret_model_json['custom_metadata'] = {'key': 'value'}
        service_credentials_secret_model_json['description'] = 'Extended description for this secret.'
        service_credentials_secret_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_model_json['labels'] = ['my-label']
        service_credentials_secret_model_json['secret_group_id'] = 'default'
        service_credentials_secret_model_json['secret_type'] = 'service_credentials'
        service_credentials_secret_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_model_json['versions_total'] = 0
        service_credentials_secret_model_json['rotation'] = rotation_policy_model
        service_credentials_secret_model_json['ttl'] = '1d'
        service_credentials_secret_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        service_credentials_secret_model_json['source_service'] = service_credentials_secret_source_service_ro_model
        service_credentials_secret_model_json['credentials'] = service_credentials_secret_credentials_model

        # Construct a model instance of ServiceCredentialsSecret by calling from_dict on the json representation
        service_credentials_secret_model = ServiceCredentialsSecret.from_dict(service_credentials_secret_model_json)
        assert service_credentials_secret_model != False

        # Construct a model instance of ServiceCredentialsSecret by calling from_dict on the json representation
        service_credentials_secret_model_dict = ServiceCredentialsSecret.from_dict(
            service_credentials_secret_model_json).__dict__
        service_credentials_secret_model2 = ServiceCredentialsSecret(**service_credentials_secret_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_model == service_credentials_secret_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_model_json2 = service_credentials_secret_model.to_dict()
        assert service_credentials_secret_model_json2 == service_credentials_secret_model_json


class TestModel_ServiceCredentialsSecretMetadata:
    """
    Test Class for ServiceCredentialsSecretMetadata
    """

    def test_service_credentials_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        service_credentials_source_service_instance_model = {}  # ServiceCredentialsSourceServiceInstance
        service_credentials_source_service_instance_model['crn'] = 'testString'

        service_credentials_source_service_parameters_model = {}  # ServiceCredentialsSourceServiceParameters
        service_credentials_source_service_parameters_model['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model['foo'] = 'testString'

        service_credentials_source_service_role_model = {}  # ServiceCredentialsSourceServiceRole
        service_credentials_source_service_role_model['crn'] = 'testString'

        service_credentials_source_service_iam_apikey_model = {}  # ServiceCredentialsSourceServiceIamApikey

        service_credentials_source_service_iam_role_model = {}  # ServiceCredentialsSourceServiceIamRole

        service_credentials_source_service_iam_serviceid_model = {}  # ServiceCredentialsSourceServiceIamServiceid

        service_credentials_source_service_iam_model = {}  # ServiceCredentialsSourceServiceIam
        service_credentials_source_service_iam_model['apikey'] = service_credentials_source_service_iam_apikey_model
        service_credentials_source_service_iam_model['role'] = service_credentials_source_service_iam_role_model
        service_credentials_source_service_iam_model[
            'serviceid'] = service_credentials_source_service_iam_serviceid_model

        service_credentials_resource_key_model = {}  # ServiceCredentialsResourceKey

        service_credentials_secret_source_service_ro_model = {}  # ServiceCredentialsSecretSourceServiceRO
        service_credentials_secret_source_service_ro_model[
            'instance'] = service_credentials_source_service_instance_model
        service_credentials_secret_source_service_ro_model[
            'parameters'] = service_credentials_source_service_parameters_model
        service_credentials_secret_source_service_ro_model['role'] = service_credentials_source_service_role_model
        service_credentials_secret_source_service_ro_model['iam'] = service_credentials_source_service_iam_model
        service_credentials_secret_source_service_ro_model['resource_key'] = service_credentials_resource_key_model

        # Construct a json representation of a ServiceCredentialsSecretMetadata model
        service_credentials_secret_metadata_model_json = {}
        service_credentials_secret_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        service_credentials_secret_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_metadata_model_json['crn'] = 'testString'
        service_credentials_secret_metadata_model_json['custom_metadata'] = {'key': 'value'}
        service_credentials_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        service_credentials_secret_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_metadata_model_json['labels'] = ['my-label']
        service_credentials_secret_metadata_model_json['secret_group_id'] = 'default'
        service_credentials_secret_metadata_model_json['secret_type'] = 'service_credentials'
        service_credentials_secret_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_metadata_model_json['versions_total'] = 0
        service_credentials_secret_metadata_model_json['rotation'] = rotation_policy_model
        service_credentials_secret_metadata_model_json['ttl'] = '1d'
        service_credentials_secret_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        service_credentials_secret_metadata_model_json[
            'source_service'] = service_credentials_secret_source_service_ro_model

        # Construct a model instance of ServiceCredentialsSecretMetadata by calling from_dict on the json representation
        service_credentials_secret_metadata_model = ServiceCredentialsSecretMetadata.from_dict(
            service_credentials_secret_metadata_model_json)
        assert service_credentials_secret_metadata_model != False

        # Construct a model instance of ServiceCredentialsSecretMetadata by calling from_dict on the json representation
        service_credentials_secret_metadata_model_dict = ServiceCredentialsSecretMetadata.from_dict(
            service_credentials_secret_metadata_model_json).__dict__
        service_credentials_secret_metadata_model2 = ServiceCredentialsSecretMetadata(
            **service_credentials_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_metadata_model == service_credentials_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_metadata_model_json2 = service_credentials_secret_metadata_model.to_dict()
        assert service_credentials_secret_metadata_model_json2 == service_credentials_secret_metadata_model_json


class TestModel_ServiceCredentialsSecretMetadataPatch:
    """
    Test Class for ServiceCredentialsSecretMetadataPatch
    """

    def test_service_credentials_secret_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        # Construct a json representation of a ServiceCredentialsSecretMetadataPatch model
        service_credentials_secret_metadata_patch_model_json = {}
        service_credentials_secret_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        service_credentials_secret_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        service_credentials_secret_metadata_patch_model_json['labels'] = ['my-label']
        service_credentials_secret_metadata_patch_model_json['name'] = 'my-secret-example'
        service_credentials_secret_metadata_patch_model_json['rotation'] = rotation_policy_model
        service_credentials_secret_metadata_patch_model_json['ttl'] = '1d'

        # Construct a model instance of ServiceCredentialsSecretMetadataPatch by calling from_dict on the json representation
        service_credentials_secret_metadata_patch_model = ServiceCredentialsSecretMetadataPatch.from_dict(
            service_credentials_secret_metadata_patch_model_json)
        assert service_credentials_secret_metadata_patch_model != False

        # Construct a model instance of ServiceCredentialsSecretMetadataPatch by calling from_dict on the json representation
        service_credentials_secret_metadata_patch_model_dict = ServiceCredentialsSecretMetadataPatch.from_dict(
            service_credentials_secret_metadata_patch_model_json).__dict__
        service_credentials_secret_metadata_patch_model2 = ServiceCredentialsSecretMetadataPatch(
            **service_credentials_secret_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_metadata_patch_model == service_credentials_secret_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_metadata_patch_model_json2 = service_credentials_secret_metadata_patch_model.to_dict()
        assert service_credentials_secret_metadata_patch_model_json2 == service_credentials_secret_metadata_patch_model_json


class TestModel_ServiceCredentialsSecretPrototype:
    """
    Test Class for ServiceCredentialsSecretPrototype
    """

    def test_service_credentials_secret_prototype_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        service_credentials_source_service_instance_model = {}  # ServiceCredentialsSourceServiceInstance
        service_credentials_source_service_instance_model['crn'] = 'testString'

        service_credentials_source_service_parameters_model = {}  # ServiceCredentialsSourceServiceParameters
        service_credentials_source_service_parameters_model['serviceid_crn'] = 'testString'
        service_credentials_source_service_parameters_model['foo'] = 'testString'

        service_credentials_source_service_role_model = {}  # ServiceCredentialsSourceServiceRole
        service_credentials_source_service_role_model['crn'] = 'testString'

        service_credentials_secret_source_service_model = {}  # ServiceCredentialsSecretSourceService
        service_credentials_secret_source_service_model['instance'] = service_credentials_source_service_instance_model
        service_credentials_secret_source_service_model[
            'parameters'] = service_credentials_source_service_parameters_model
        service_credentials_secret_source_service_model['role'] = service_credentials_source_service_role_model

        # Construct a json representation of a ServiceCredentialsSecretPrototype model
        service_credentials_secret_prototype_model_json = {}
        service_credentials_secret_prototype_model_json['custom_metadata'] = {'key': 'value'}
        service_credentials_secret_prototype_model_json['description'] = 'Extended description for this secret.'
        service_credentials_secret_prototype_model_json['labels'] = ['my-label']
        service_credentials_secret_prototype_model_json['name'] = 'my-secret-example'
        service_credentials_secret_prototype_model_json['rotation'] = rotation_policy_model
        service_credentials_secret_prototype_model_json['secret_group_id'] = 'default'
        service_credentials_secret_prototype_model_json['secret_type'] = 'service_credentials'
        service_credentials_secret_prototype_model_json[
            'source_service'] = service_credentials_secret_source_service_model
        service_credentials_secret_prototype_model_json['ttl'] = '1d'
        service_credentials_secret_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ServiceCredentialsSecretPrototype by calling from_dict on the json representation
        service_credentials_secret_prototype_model = ServiceCredentialsSecretPrototype.from_dict(
            service_credentials_secret_prototype_model_json)
        assert service_credentials_secret_prototype_model != False

        # Construct a model instance of ServiceCredentialsSecretPrototype by calling from_dict on the json representation
        service_credentials_secret_prototype_model_dict = ServiceCredentialsSecretPrototype.from_dict(
            service_credentials_secret_prototype_model_json).__dict__
        service_credentials_secret_prototype_model2 = ServiceCredentialsSecretPrototype(
            **service_credentials_secret_prototype_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_prototype_model == service_credentials_secret_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_prototype_model_json2 = service_credentials_secret_prototype_model.to_dict()
        assert service_credentials_secret_prototype_model_json2 == service_credentials_secret_prototype_model_json


class TestModel_ServiceCredentialsSecretVersion:
    """
    Test Class for ServiceCredentialsSecretVersion
    """

    def test_service_credentials_secret_version_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        service_credentials_resource_key_model = {}  # ServiceCredentialsResourceKey

        service_credentials_secret_credentials_model = {}  # ServiceCredentialsSecretCredentials
        service_credentials_secret_credentials_model['foo'] = 'testString'

        # Construct a json representation of a ServiceCredentialsSecretVersion model
        service_credentials_secret_version_model_json = {}
        service_credentials_secret_version_model_json['auto_rotated'] = True
        service_credentials_secret_version_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        service_credentials_secret_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_version_model_json['secret_type'] = 'service_credentials'
        service_credentials_secret_version_model_json['secret_group_id'] = 'default'
        service_credentials_secret_version_model_json['payload_available'] = True
        service_credentials_secret_version_model_json['alias'] = 'current'
        service_credentials_secret_version_model_json['version_custom_metadata'] = {'key': 'value'}
        service_credentials_secret_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        service_credentials_secret_version_model_json['resource_key'] = service_credentials_resource_key_model
        service_credentials_secret_version_model_json['credentials'] = service_credentials_secret_credentials_model

        # Construct a model instance of ServiceCredentialsSecretVersion by calling from_dict on the json representation
        service_credentials_secret_version_model = ServiceCredentialsSecretVersion.from_dict(
            service_credentials_secret_version_model_json)
        assert service_credentials_secret_version_model != False

        # Construct a model instance of ServiceCredentialsSecretVersion by calling from_dict on the json representation
        service_credentials_secret_version_model_dict = ServiceCredentialsSecretVersion.from_dict(
            service_credentials_secret_version_model_json).__dict__
        service_credentials_secret_version_model2 = ServiceCredentialsSecretVersion(
            **service_credentials_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_version_model == service_credentials_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_version_model_json2 = service_credentials_secret_version_model.to_dict()
        assert service_credentials_secret_version_model_json2 == service_credentials_secret_version_model_json


class TestModel_ServiceCredentialsSecretVersionMetadata:
    """
    Test Class for ServiceCredentialsSecretVersionMetadata
    """

    def test_service_credentials_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        service_credentials_resource_key_model = {}  # ServiceCredentialsResourceKey

        # Construct a json representation of a ServiceCredentialsSecretVersionMetadata model
        service_credentials_secret_version_metadata_model_json = {}
        service_credentials_secret_version_metadata_model_json['auto_rotated'] = True
        service_credentials_secret_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        service_credentials_secret_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        service_credentials_secret_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_version_metadata_model_json['secret_type'] = 'service_credentials'
        service_credentials_secret_version_metadata_model_json['secret_group_id'] = 'default'
        service_credentials_secret_version_metadata_model_json['payload_available'] = True
        service_credentials_secret_version_metadata_model_json['alias'] = 'current'
        service_credentials_secret_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        service_credentials_secret_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        service_credentials_secret_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        service_credentials_secret_version_metadata_model_json['resource_key'] = service_credentials_resource_key_model

        # Construct a model instance of ServiceCredentialsSecretVersionMetadata by calling from_dict on the json representation
        service_credentials_secret_version_metadata_model = ServiceCredentialsSecretVersionMetadata.from_dict(
            service_credentials_secret_version_metadata_model_json)
        assert service_credentials_secret_version_metadata_model != False

        # Construct a model instance of ServiceCredentialsSecretVersionMetadata by calling from_dict on the json representation
        service_credentials_secret_version_metadata_model_dict = ServiceCredentialsSecretVersionMetadata.from_dict(
            service_credentials_secret_version_metadata_model_json).__dict__
        service_credentials_secret_version_metadata_model2 = ServiceCredentialsSecretVersionMetadata(
            **service_credentials_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_version_metadata_model == service_credentials_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_version_metadata_model_json2 = service_credentials_secret_version_metadata_model.to_dict()
        assert service_credentials_secret_version_metadata_model_json2 == service_credentials_secret_version_metadata_model_json


class TestModel_ServiceCredentialsSecretVersionPrototype:
    """
    Test Class for ServiceCredentialsSecretVersionPrototype
    """

    def test_service_credentials_secret_version_prototype_serialization(self):
        """
        Test serialization/deserialization for ServiceCredentialsSecretVersionPrototype
        """

        # Construct a json representation of a ServiceCredentialsSecretVersionPrototype model
        service_credentials_secret_version_prototype_model_json = {}
        service_credentials_secret_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        service_credentials_secret_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of ServiceCredentialsSecretVersionPrototype by calling from_dict on the json representation
        service_credentials_secret_version_prototype_model = ServiceCredentialsSecretVersionPrototype.from_dict(
            service_credentials_secret_version_prototype_model_json)
        assert service_credentials_secret_version_prototype_model != False

        # Construct a model instance of ServiceCredentialsSecretVersionPrototype by calling from_dict on the json representation
        service_credentials_secret_version_prototype_model_dict = ServiceCredentialsSecretVersionPrototype.from_dict(
            service_credentials_secret_version_prototype_model_json).__dict__
        service_credentials_secret_version_prototype_model2 = ServiceCredentialsSecretVersionPrototype(
            **service_credentials_secret_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert service_credentials_secret_version_prototype_model == service_credentials_secret_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        service_credentials_secret_version_prototype_model_json2 = service_credentials_secret_version_prototype_model.to_dict()
        assert service_credentials_secret_version_prototype_model_json2 == service_credentials_secret_version_prototype_model_json


class TestModel_UsernamePasswordSecret:
    """
    Test Class for UsernamePasswordSecret
    """

    def test_username_password_secret_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        password_generation_policy_ro_model = {}  # PasswordGenerationPolicyRO
        password_generation_policy_ro_model['length'] = 12
        password_generation_policy_ro_model['include_digits'] = True
        password_generation_policy_ro_model['include_symbols'] = True
        password_generation_policy_ro_model['include_uppercase'] = True

        # Construct a json representation of a UsernamePasswordSecret model
        username_password_secret_model_json = {}
        username_password_secret_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        username_password_secret_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_model_json['crn'] = 'testString'
        username_password_secret_model_json['custom_metadata'] = {'key': 'value'}
        username_password_secret_model_json['description'] = 'Extended description for this secret.'
        username_password_secret_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_model_json['labels'] = ['my-label']
        username_password_secret_model_json['secret_group_id'] = 'default'
        username_password_secret_model_json['secret_type'] = 'username_password'
        username_password_secret_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_model_json['versions_total'] = 0
        username_password_secret_model_json['rotation'] = rotation_policy_model
        username_password_secret_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        username_password_secret_model_json['password_generation_policy'] = password_generation_policy_ro_model
        username_password_secret_model_json['username'] = 'testString'
        username_password_secret_model_json['password'] = 'testString'

        # Construct a model instance of UsernamePasswordSecret by calling from_dict on the json representation
        username_password_secret_model = UsernamePasswordSecret.from_dict(username_password_secret_model_json)
        assert username_password_secret_model != False

        # Construct a model instance of UsernamePasswordSecret by calling from_dict on the json representation
        username_password_secret_model_dict = UsernamePasswordSecret.from_dict(
            username_password_secret_model_json).__dict__
        username_password_secret_model2 = UsernamePasswordSecret(**username_password_secret_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_model == username_password_secret_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_model_json2 = username_password_secret_model.to_dict()
        assert username_password_secret_model_json2 == username_password_secret_model_json


class TestModel_UsernamePasswordSecretMetadata:
    """
    Test Class for UsernamePasswordSecretMetadata
    """

    def test_username_password_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        password_generation_policy_ro_model = {}  # PasswordGenerationPolicyRO
        password_generation_policy_ro_model['length'] = 12
        password_generation_policy_ro_model['include_digits'] = True
        password_generation_policy_ro_model['include_symbols'] = True
        password_generation_policy_ro_model['include_uppercase'] = True

        # Construct a json representation of a UsernamePasswordSecretMetadata model
        username_password_secret_metadata_model_json = {}
        username_password_secret_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        username_password_secret_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_metadata_model_json['crn'] = 'testString'
        username_password_secret_metadata_model_json['custom_metadata'] = {'key': 'value'}
        username_password_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        username_password_secret_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_metadata_model_json['labels'] = ['my-label']
        username_password_secret_metadata_model_json['secret_group_id'] = 'default'
        username_password_secret_metadata_model_json['secret_type'] = 'username_password'
        username_password_secret_metadata_model_json['updated_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_metadata_model_json['versions_total'] = 0
        username_password_secret_metadata_model_json['rotation'] = rotation_policy_model
        username_password_secret_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        username_password_secret_metadata_model_json['password_generation_policy'] = password_generation_policy_ro_model

        # Construct a model instance of UsernamePasswordSecretMetadata by calling from_dict on the json representation
        username_password_secret_metadata_model = UsernamePasswordSecretMetadata.from_dict(
            username_password_secret_metadata_model_json)
        assert username_password_secret_metadata_model != False

        # Construct a model instance of UsernamePasswordSecretMetadata by calling from_dict on the json representation
        username_password_secret_metadata_model_dict = UsernamePasswordSecretMetadata.from_dict(
            username_password_secret_metadata_model_json).__dict__
        username_password_secret_metadata_model2 = UsernamePasswordSecretMetadata(
            **username_password_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_metadata_model == username_password_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_metadata_model_json2 = username_password_secret_metadata_model.to_dict()
        assert username_password_secret_metadata_model_json2 == username_password_secret_metadata_model_json


class TestModel_UsernamePasswordSecretMetadataPatch:
    """
    Test Class for UsernamePasswordSecretMetadataPatch
    """

    def test_username_password_secret_metadata_patch_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretMetadataPatch
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        password_generation_policy_patch_model = {}  # PasswordGenerationPolicyPatch
        password_generation_policy_patch_model['length'] = 12
        password_generation_policy_patch_model['include_digits'] = True
        password_generation_policy_patch_model['include_symbols'] = True
        password_generation_policy_patch_model['include_uppercase'] = True

        # Construct a json representation of a UsernamePasswordSecretMetadataPatch model
        username_password_secret_metadata_patch_model_json = {}
        username_password_secret_metadata_patch_model_json['name'] = 'my-secret-example'
        username_password_secret_metadata_patch_model_json['description'] = 'Extended description for this secret.'
        username_password_secret_metadata_patch_model_json['labels'] = ['my-label']
        username_password_secret_metadata_patch_model_json['custom_metadata'] = {'key': 'value'}
        username_password_secret_metadata_patch_model_json['rotation'] = rotation_policy_model
        username_password_secret_metadata_patch_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        username_password_secret_metadata_patch_model_json[
            'password_generation_policy'] = password_generation_policy_patch_model

        # Construct a model instance of UsernamePasswordSecretMetadataPatch by calling from_dict on the json representation
        username_password_secret_metadata_patch_model = UsernamePasswordSecretMetadataPatch.from_dict(
            username_password_secret_metadata_patch_model_json)
        assert username_password_secret_metadata_patch_model != False

        # Construct a model instance of UsernamePasswordSecretMetadataPatch by calling from_dict on the json representation
        username_password_secret_metadata_patch_model_dict = UsernamePasswordSecretMetadataPatch.from_dict(
            username_password_secret_metadata_patch_model_json).__dict__
        username_password_secret_metadata_patch_model2 = UsernamePasswordSecretMetadataPatch(
            **username_password_secret_metadata_patch_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_metadata_patch_model == username_password_secret_metadata_patch_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_metadata_patch_model_json2 = username_password_secret_metadata_patch_model.to_dict()
        assert username_password_secret_metadata_patch_model_json2 == username_password_secret_metadata_patch_model_json


class TestModel_UsernamePasswordSecretPrototype:
    """
    Test Class for UsernamePasswordSecretPrototype
    """

    def test_username_password_secret_prototype_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretPrototype
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_policy_model = {}  # CommonRotationPolicy
        rotation_policy_model['auto_rotate'] = True
        rotation_policy_model['interval'] = 1
        rotation_policy_model['unit'] = 'day'

        password_generation_policy_model = {}  # PasswordGenerationPolicy
        password_generation_policy_model['length'] = 32
        password_generation_policy_model['include_digits'] = True
        password_generation_policy_model['include_symbols'] = True
        password_generation_policy_model['include_uppercase'] = True

        # Construct a json representation of a UsernamePasswordSecretPrototype model
        username_password_secret_prototype_model_json = {}
        username_password_secret_prototype_model_json['secret_type'] = 'username_password'
        username_password_secret_prototype_model_json['name'] = 'my-secret-example'
        username_password_secret_prototype_model_json['description'] = 'Extended description for this secret.'
        username_password_secret_prototype_model_json['secret_group_id'] = 'default'
        username_password_secret_prototype_model_json['labels'] = ['my-label']
        username_password_secret_prototype_model_json['username'] = 'testString'
        username_password_secret_prototype_model_json['password'] = 'testString'
        username_password_secret_prototype_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        username_password_secret_prototype_model_json['custom_metadata'] = {'key': 'value'}
        username_password_secret_prototype_model_json['version_custom_metadata'] = {'key': 'value'}
        username_password_secret_prototype_model_json['rotation'] = rotation_policy_model
        username_password_secret_prototype_model_json['password_generation_policy'] = password_generation_policy_model

        # Construct a model instance of UsernamePasswordSecretPrototype by calling from_dict on the json representation
        username_password_secret_prototype_model = UsernamePasswordSecretPrototype.from_dict(
            username_password_secret_prototype_model_json)
        assert username_password_secret_prototype_model != False

        # Construct a model instance of UsernamePasswordSecretPrototype by calling from_dict on the json representation
        username_password_secret_prototype_model_dict = UsernamePasswordSecretPrototype.from_dict(
            username_password_secret_prototype_model_json).__dict__
        username_password_secret_prototype_model2 = UsernamePasswordSecretPrototype(
            **username_password_secret_prototype_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_prototype_model == username_password_secret_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_prototype_model_json2 = username_password_secret_prototype_model.to_dict()
        assert username_password_secret_prototype_model_json2 == username_password_secret_prototype_model_json


class TestModel_UsernamePasswordSecretVersion:
    """
    Test Class for UsernamePasswordSecretVersion
    """

    def test_username_password_secret_version_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretVersion
        """

        # Construct a json representation of a UsernamePasswordSecretVersion model
        username_password_secret_version_model_json = {}
        username_password_secret_version_model_json['auto_rotated'] = True
        username_password_secret_version_model_json['created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        username_password_secret_version_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_version_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_version_model_json['secret_type'] = 'username_password'
        username_password_secret_version_model_json['secret_group_id'] = 'default'
        username_password_secret_version_model_json['payload_available'] = True
        username_password_secret_version_model_json['alias'] = 'current'
        username_password_secret_version_model_json['version_custom_metadata'] = {'key': 'value'}
        username_password_secret_version_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_version_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'
        username_password_secret_version_model_json['username'] = 'testString'
        username_password_secret_version_model_json['password'] = 'testString'

        # Construct a model instance of UsernamePasswordSecretVersion by calling from_dict on the json representation
        username_password_secret_version_model = UsernamePasswordSecretVersion.from_dict(
            username_password_secret_version_model_json)
        assert username_password_secret_version_model != False

        # Construct a model instance of UsernamePasswordSecretVersion by calling from_dict on the json representation
        username_password_secret_version_model_dict = UsernamePasswordSecretVersion.from_dict(
            username_password_secret_version_model_json).__dict__
        username_password_secret_version_model2 = UsernamePasswordSecretVersion(
            **username_password_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_version_model == username_password_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_version_model_json2 = username_password_secret_version_model.to_dict()
        assert username_password_secret_version_model_json2 == username_password_secret_version_model_json


class TestModel_UsernamePasswordSecretVersionMetadata:
    """
    Test Class for UsernamePasswordSecretVersionMetadata
    """

    def test_username_password_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretVersionMetadata
        """

        # Construct a json representation of a UsernamePasswordSecretVersionMetadata model
        username_password_secret_version_metadata_model_json = {}
        username_password_secret_version_metadata_model_json['auto_rotated'] = True
        username_password_secret_version_metadata_model_json[
            'created_by'] = 'iam-ServiceId-e4a2f0a4-3c76-4bef-b1f2-fbeae11c0f21'
        username_password_secret_version_metadata_model_json['created_at'] = '2022-04-12T23:20:50.520000Z'
        username_password_secret_version_metadata_model_json['id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_version_metadata_model_json['secret_type'] = 'username_password'
        username_password_secret_version_metadata_model_json['secret_group_id'] = 'default'
        username_password_secret_version_metadata_model_json['payload_available'] = True
        username_password_secret_version_metadata_model_json['alias'] = 'current'
        username_password_secret_version_metadata_model_json['version_custom_metadata'] = {'key': 'value'}
        username_password_secret_version_metadata_model_json['secret_id'] = 'b49ad24d-81d4-5ebc-b9b9-b0937d1c84d5'
        username_password_secret_version_metadata_model_json['expiration_date'] = '2033-04-12T23:20:50.520000Z'

        # Construct a model instance of UsernamePasswordSecretVersionMetadata by calling from_dict on the json representation
        username_password_secret_version_metadata_model = UsernamePasswordSecretVersionMetadata.from_dict(
            username_password_secret_version_metadata_model_json)
        assert username_password_secret_version_metadata_model != False

        # Construct a model instance of UsernamePasswordSecretVersionMetadata by calling from_dict on the json representation
        username_password_secret_version_metadata_model_dict = UsernamePasswordSecretVersionMetadata.from_dict(
            username_password_secret_version_metadata_model_json).__dict__
        username_password_secret_version_metadata_model2 = UsernamePasswordSecretVersionMetadata(
            **username_password_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_version_metadata_model == username_password_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_version_metadata_model_json2 = username_password_secret_version_metadata_model.to_dict()
        assert username_password_secret_version_metadata_model_json2 == username_password_secret_version_metadata_model_json


class TestModel_UsernamePasswordSecretVersionPrototype:
    """
    Test Class for UsernamePasswordSecretVersionPrototype
    """

    def test_username_password_secret_version_prototype_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretVersionPrototype
        """

        # Construct a json representation of a UsernamePasswordSecretVersionPrototype model
        username_password_secret_version_prototype_model_json = {}
        username_password_secret_version_prototype_model_json['password'] = 'testString'
        username_password_secret_version_prototype_model_json['custom_metadata'] = {'key': 'value'}
        username_password_secret_version_prototype_model_json['version_custom_metadata'] = {'key': 'value'}

        # Construct a model instance of UsernamePasswordSecretVersionPrototype by calling from_dict on the json representation
        username_password_secret_version_prototype_model = UsernamePasswordSecretVersionPrototype.from_dict(
            username_password_secret_version_prototype_model_json)
        assert username_password_secret_version_prototype_model != False

        # Construct a model instance of UsernamePasswordSecretVersionPrototype by calling from_dict on the json representation
        username_password_secret_version_prototype_model_dict = UsernamePasswordSecretVersionPrototype.from_dict(
            username_password_secret_version_prototype_model_json).__dict__
        username_password_secret_version_prototype_model2 = UsernamePasswordSecretVersionPrototype(
            **username_password_secret_version_prototype_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_version_prototype_model == username_password_secret_version_prototype_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_version_prototype_model_json2 = username_password_secret_version_prototype_model.to_dict()
        assert username_password_secret_version_prototype_model_json2 == username_password_secret_version_prototype_model_json

# endregion
##############################################################################
# End of Model Tests
##############################################################################
