# -*- coding: utf-8 -*-
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

"""
Unit Tests for SecretsManagerV1
"""

from datetime import datetime, timezone
from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
import inspect
import json
import pytest
import re
import requests
import responses
import urllib
from ibm_secrets_manager_sdk.secrets_manager_v1 import *

service = SecretsManagerV1(
    authenticator=NoAuthAuthenticator()
)

base_url = 'https://secrets-manager.cloud.ibm.com'
service.set_service_url(base_url)


##############################################################################
# Start of Service: Config
##############################################################################
# region

class TestPutConfig():
    """
    Test Class for put_config
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_put_config_all_params(self):
        """
        put_config()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/config/iam_credentials')
        responses.add(responses.PUT,
                      url,
                      status=204)

        # Construct a dict representation of a EngineConfigOneOfIAMSecretEngineRootConfig model
        engine_config_one_of_model = {}
        engine_config_one_of_model['api_key'] = 'API_KEY'

        # Set up parameter values
        secret_type = 'iam_credentials'
        engine_config_one_of = engine_config_one_of_model

        # Invoke method
        response = service.put_config(
            secret_type,
            engine_config_one_of,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == engine_config_one_of

    @responses.activate
    def test_put_config_value_error(self):
        """
        test_put_config_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/config/iam_credentials')
        responses.add(responses.PUT,
                      url,
                      status=204)

        # Construct a dict representation of a EngineConfigOneOfIAMSecretEngineRootConfig model
        engine_config_one_of_model = {}
        engine_config_one_of_model['api_key'] = 'API_KEY'

        # Set up parameter values
        secret_type = 'iam_credentials'
        engine_config_one_of = engine_config_one_of_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "engine_config_one_of": engine_config_one_of,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.put_config(**req_copy)


class TestGetConfig():
    """
    Test Class for get_config
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_config_all_params(self):
        """
        get_config()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/config/iam_credentials')
        mock_response = '{"api_key": "API_KEY", "api_key_hash": "a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91"}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'iam_credentials'

        # Invoke method
        response = service.get_config(
            secret_type,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_get_config_value_error(self):
        """
        test_get_config_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/config/iam_credentials')
        mock_response = '{"api_key": "API_KEY", "api_key_hash": "a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91"}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'iam_credentials'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_config(**req_copy)


# endregion
##############################################################################
# End of Service: Config
##############################################################################

##############################################################################
# Start of Service: Policies
##############################################################################
# region

class TestPutPolicy():
    """
    Test Class for put_policy
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_put_policy_all_params(self):
        """
        put_policy()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotation model
        secret_policy_rotation_rotation_model = {}
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a dict representation of a SecretPolicyRotation model
        secret_policy_rotation_model = {}
        secret_policy_rotation_model['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        secret_policy_rotation_model['rotation'] = secret_policy_rotation_rotation_model

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_policy_rotation_model]
        policy = 'rotation'

        # Invoke method
        response = service.put_policy(
            secret_type,
            id,
            metadata,
            resources,
            policy=policy,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'policy={}'.format(policy) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_policy_rotation_model]

    @responses.activate
    def test_put_policy_required_params(self):
        """
        test_put_policy_required_params()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotation model
        secret_policy_rotation_rotation_model = {}
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a dict representation of a SecretPolicyRotation model
        secret_policy_rotation_model = {}
        secret_policy_rotation_model['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        secret_policy_rotation_model['rotation'] = secret_policy_rotation_rotation_model

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_policy_rotation_model]

        # Invoke method
        response = service.put_policy(
            secret_type,
            id,
            metadata,
            resources,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_policy_rotation_model]

    @responses.activate
    def test_put_policy_value_error(self):
        """
        test_put_policy_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotation model
        secret_policy_rotation_rotation_model = {}
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a dict representation of a SecretPolicyRotation model
        secret_policy_rotation_model = {}
        secret_policy_rotation_model['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        secret_policy_rotation_model['rotation'] = secret_policy_rotation_rotation_model

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_policy_rotation_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.put_policy(**req_copy)


class TestGetPolicy():
    """
    Test Class for get_policy
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_policy_all_params(self):
        """
        get_policy()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'
        policy = 'rotation'

        # Invoke method
        response = service.get_policy(
            secret_type,
            id,
            policy=policy,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'policy={}'.format(policy) in query_string

    @responses.activate
    def test_get_policy_required_params(self):
        """
        test_get_policy_required_params()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'

        # Invoke method
        response = service.get_policy(
            secret_type,
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_get_policy_value_error(self):
        """
        test_get_policy_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_policy(**req_copy)


# endregion
##############################################################################
# End of Service: Policies
##############################################################################

##############################################################################
# Start of Service: SecretGroups
##############################################################################
# region

class TestCreateSecretGroup():
    """
    Test Class for create_secret_group
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_create_secret_group_all_params(self):
        """
        create_secret_group()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretGroupResource model
        secret_group_resource_model = {}
        secret_group_resource_model['name'] = 'my-secret-group'
        secret_group_resource_model['description'] = 'Extended description for this group.'
        secret_group_resource_model['foo'] = {'foo': 'bar'}

        # Set up parameter values
        metadata = collection_metadata_model
        resources = [secret_group_resource_model]

        # Invoke method
        response = service.create_secret_group(
            metadata,
            resources,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_group_resource_model]

    @responses.activate
    def test_create_secret_group_value_error(self):
        """
        test_create_secret_group_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretGroupResource model
        secret_group_resource_model = {}
        secret_group_resource_model['name'] = 'my-secret-group'
        secret_group_resource_model['description'] = 'Extended description for this group.'
        secret_group_resource_model['foo'] = {'foo': 'bar'}

        # Set up parameter values
        metadata = collection_metadata_model
        resources = [secret_group_resource_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.create_secret_group(**req_copy)


class TestListSecretGroups():
    """
    Test Class for list_secret_groups
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_list_secret_groups_all_params(self):
        """
        list_secret_groups()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.list_secret_groups()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


class TestGetSecretGroup():
    """
    Test Class for get_secret_group
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_group_all_params(self):
        """
        get_secret_group()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.get_secret_group(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_get_secret_group_value_error(self):
        """
        test_get_secret_group_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_secret_group(**req_copy)


class TestUpdateSecretGroupMetadata():
    """
    Test Class for update_secret_group_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_update_secret_group_metadata_all_params(self):
        """
        update_secret_group_metadata()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretGroupMetadataUpdatable model
        secret_group_metadata_updatable_model = {}
        secret_group_metadata_updatable_model['name'] = 'updated-secret-group-name'
        secret_group_metadata_updatable_model['description'] = 'Updated description for this group.'

        # Set up parameter values
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_group_metadata_updatable_model]

        # Invoke method
        response = service.update_secret_group_metadata(
            id,
            metadata,
            resources,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_group_metadata_updatable_model]

    @responses.activate
    def test_update_secret_group_metadata_value_error(self):
        """
        test_update_secret_group_metadata_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretGroupMetadataUpdatable model
        secret_group_metadata_updatable_model = {}
        secret_group_metadata_updatable_model['name'] = 'updated-secret-group-name'
        secret_group_metadata_updatable_model['description'] = 'Updated description for this group.'

        # Set up parameter values
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_group_metadata_updatable_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_secret_group_metadata(**req_copy)


class TestDeleteSecretGroup():
    """
    Test Class for delete_secret_group
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_delete_secret_group_all_params(self):
        """
        delete_secret_group()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.delete_secret_group(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    @responses.activate
    def test_delete_secret_group_value_error(self):
        """
        test_delete_secret_group_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secret_groups/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.delete_secret_group(**req_copy)


# endregion
##############################################################################
# End of Service: SecretGroups
##############################################################################

##############################################################################
# Start of Service: Secrets
##############################################################################
# region

class TestCreateSecret():
    """
    Test Class for create_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_create_secret_all_params(self):
        """
        create_secret()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretResourceArbitrarySecretResource model
        secret_resource_model = {}
        secret_resource_model['type'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        metadata = collection_metadata_model
        resources = [secret_resource_model]

        # Invoke method
        response = service.create_secret(
            secret_type,
            metadata,
            resources,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_resource_model]

    @responses.activate
    def test_create_secret_value_error(self):
        """
        test_create_secret_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretResourceArbitrarySecretResource model
        secret_resource_model = {}
        secret_resource_model['type'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        metadata = collection_metadata_model
        resources = [secret_resource_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.create_secret(**req_copy)


class TestListSecrets():
    """
    Test Class for list_secrets
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_list_secrets_all_params(self):
        """
        list_secrets()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        limit = 1
        offset = 0

        # Invoke method
        response = service.list_secrets(
            secret_type,
            limit=limit,
            offset=offset,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'limit={}'.format(limit) in query_string
        assert 'offset={}'.format(offset) in query_string

    @responses.activate
    def test_list_secrets_required_params(self):
        """
        test_list_secrets_required_params()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'

        # Invoke method
        response = service.list_secrets(
            secret_type,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_list_secrets_value_error(self):
        """
        test_list_secrets_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.list_secrets(**req_copy)


class TestListAllSecrets():
    """
    Test Class for list_all_secrets
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_list_all_secrets_all_params(self):
        """
        list_all_secrets()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        limit = 1
        offset = 0
        search = 'testString'
        sort_by = 'id'

        # Invoke method
        response = service.list_all_secrets(
            limit=limit,
            offset=offset,
            search=search,
            sort_by=sort_by,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'limit={}'.format(limit) in query_string
        assert 'offset={}'.format(offset) in query_string
        assert 'search={}'.format(search) in query_string
        assert 'sort_by={}'.format(sort_by) in query_string

    @responses.activate
    def test_list_all_secrets_required_params(self):
        """
        test_list_all_secrets_required_params()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.list_all_secrets()

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


class TestGetSecret():
    """
    Test Class for get_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_all_params(self):
        """
        get_secret()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = service.get_secret(
            secret_type,
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_get_secret_value_error(self):
        """
        test_get_secret_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_secret(**req_copy)


class TestUpdateSecret():
    """
    Test Class for update_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_update_secret_all_params(self):
        """
        update_secret()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a SecretActionOneOfRotateArbitrarySecretBody model
        secret_action_one_of_model = {}
        secret_action_one_of_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        action = 'rotate'
        secret_action_one_of = secret_action_one_of_model

        # Invoke method
        response = service.update_secret(
            secret_type,
            id,
            action,
            secret_action_one_of,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?', 1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'action={}'.format(action) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_action_one_of

    @responses.activate
    def test_update_secret_value_error(self):
        """
        test_update_secret_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"type": "type", "id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "auto_rotated": true}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a SecretActionOneOfRotateArbitrarySecretBody model
        secret_action_one_of_model = {}
        secret_action_one_of_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        action = 'rotate'
        secret_action_one_of = secret_action_one_of_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "action": action,
            "secret_action_one_of": secret_action_one_of,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_secret(**req_copy)


class TestDeleteSecret():
    """
    Test Class for delete_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_delete_secret_all_params(self):
        """
        delete_secret()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = service.delete_secret(
            secret_type,
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204

    @responses.activate
    def test_delete_secret_value_error(self):
        """
        test_delete_secret_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.delete_secret(**req_copy)


class TestGetSecretMetadata():
    """
    Test Class for get_secret_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_metadata_all_params(self):
        """
        get_secret_metadata()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2030-04-01T09:30:00.000Z", "ttl": {"anyKey": "anyValue"}, "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = service.get_secret_metadata(
            secret_type,
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200

    @responses.activate
    def test_get_secret_metadata_value_error(self):
        """
        test_get_secret_metadata_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2030-04-01T09:30:00.000Z", "ttl": {"anyKey": "anyValue"}, "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_secret_metadata(**req_copy)


class TestUpdateSecretMetadata():
    """
    Test Class for update_secret_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_update_secret_metadata_all_params(self):
        """
        update_secret_metadata()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2030-04-01T09:30:00.000Z", "ttl": {"anyKey": "anyValue"}, "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretMetadata model
        secret_metadata_model = {}
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model['ttl'] = {'foo': 'bar'}

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_metadata_model]

        # Invoke method
        response = service.update_secret_metadata(
            secret_type,
            id,
            metadata,
            resources,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['metadata'] == collection_metadata_model
        assert req_body['resources'] == [secret_metadata_model]

    @responses.activate
    def test_update_secret_metadata_value_error(self):
        """
        test_update_secret_metadata_value_error()
        """
        # Set up mock
        url = self.preprocess_url(base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.secret+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 1, "state_description": "Active", "secret_type": "arbitrary", "expiration_date": "2030-04-01T09:30:00.000Z", "ttl": {"anyKey": "anyValue"}, "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretMetadata model
        secret_metadata_model = {}
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model['ttl'] = {'foo': 'bar'}

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_metadata_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key: val if key is not param else None for (key, val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_secret_metadata(**req_copy)


# endregion
##############################################################################
# End of Service: Secrets
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region
class TestCollectionMetadata():
    """
    Test Class for CollectionMetadata
    """

    def test_collection_metadata_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadata
        """

        # Construct a json representation of a CollectionMetadata model
        collection_metadata_model_json = {}
        collection_metadata_model_json['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model_json['collection_total'] = 1

        # Construct a model instance of CollectionMetadata by calling from_dict on the json representation
        collection_metadata_model = CollectionMetadata.from_dict(collection_metadata_model_json)
        assert collection_metadata_model != False

        # Construct a model instance of CollectionMetadata by calling from_dict on the json representation
        collection_metadata_model_dict = CollectionMetadata.from_dict(collection_metadata_model_json).__dict__
        collection_metadata_model2 = CollectionMetadata(**collection_metadata_model_dict)

        # Verify the model instances are equivalent
        assert collection_metadata_model == collection_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        collection_metadata_model_json2 = collection_metadata_model.to_dict()
        assert collection_metadata_model_json2 == collection_metadata_model_json


class TestCreateSecret():
    """
    Test Class for CreateSecret
    """

    def test_create_secret_serialization(self):
        """
        Test serialization/deserialization for CreateSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        secret_resource_model = {}  # SecretResourceArbitrarySecretResource
        secret_resource_model['type'] = 'testString'
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['versions'] = [secret_version_model]
        secret_resource_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = {'foo': 'bar'}

        # Construct a json representation of a CreateSecret model
        create_secret_model_json = {}
        create_secret_model_json['metadata'] = collection_metadata_model
        create_secret_model_json['resources'] = [secret_resource_model]

        # Construct a model instance of CreateSecret by calling from_dict on the json representation
        create_secret_model = CreateSecret.from_dict(create_secret_model_json)
        assert create_secret_model != False

        # Construct a model instance of CreateSecret by calling from_dict on the json representation
        create_secret_model_dict = CreateSecret.from_dict(create_secret_model_json).__dict__
        create_secret_model2 = CreateSecret(**create_secret_model_dict)

        # Verify the model instances are equivalent
        assert create_secret_model == create_secret_model2

        # Convert model instance back to dict and verify no loss of data
        create_secret_model_json2 = create_secret_model.to_dict()
        assert create_secret_model_json2 == create_secret_model_json


class TestGetSecret():
    """
    Test Class for GetSecret
    """

    def test_get_secret_serialization(self):
        """
        Test serialization/deserialization for GetSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        secret_resource_model = {}  # SecretResourceArbitrarySecretResource
        secret_resource_model['type'] = 'testString'
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['versions'] = [secret_version_model]
        secret_resource_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = {'foo': 'bar'}

        # Construct a json representation of a GetSecret model
        get_secret_model_json = {}
        get_secret_model_json['metadata'] = collection_metadata_model
        get_secret_model_json['resources'] = [secret_resource_model]

        # Construct a model instance of GetSecret by calling from_dict on the json representation
        get_secret_model = GetSecret.from_dict(get_secret_model_json)
        assert get_secret_model != False

        # Construct a model instance of GetSecret by calling from_dict on the json representation
        get_secret_model_dict = GetSecret.from_dict(get_secret_model_json).__dict__
        get_secret_model2 = GetSecret(**get_secret_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_model == get_secret_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_model_json2 = get_secret_model.to_dict()
        assert get_secret_model_json2 == get_secret_model_json


class TestGetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem():
    """
    Test Class for GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem
    """

    def test_get_secret_policies_one_of_get_secret_policy_rotation_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_policy_rotation_rotation_model = {}  # SecretPolicyRotationRotation
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a json representation of a GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem model
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json = {}
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json['id'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json[
            'crn'] = 'crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json[
            'creation_date'] = '2020-01-28T18:40:40.123456Z'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json['created_by'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json[
            'last_update_date'] = '2020-01-28T18:40:40.123456Z'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json['updated_by'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json[
            'type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json[
            'rotation'] = secret_policy_rotation_rotation_model

        # Construct a model instance of GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem by calling from_dict on the json representation
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model = GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem.from_dict(
            get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json)
        assert get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model != False

        # Construct a model instance of GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem by calling from_dict on the json representation
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_dict = GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem.from_dict(
            get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json).__dict__
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model2 = GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem(
            **get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model == get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json2 = get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model.to_dict()
        assert get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json2 == get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model_json


class TestListSecrets():
    """
    Test Class for ListSecrets
    """

    def test_list_secrets_serialization(self):
        """
        Test serialization/deserialization for ListSecrets
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        secret_resource_model = {}  # SecretResourceArbitrarySecretResource
        secret_resource_model['type'] = 'testString'
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['versions'] = [secret_version_model]
        secret_resource_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = {'foo': 'bar'}

        # Construct a json representation of a ListSecrets model
        list_secrets_model_json = {}
        list_secrets_model_json['metadata'] = collection_metadata_model
        list_secrets_model_json['resources'] = [secret_resource_model]

        # Construct a model instance of ListSecrets by calling from_dict on the json representation
        list_secrets_model = ListSecrets.from_dict(list_secrets_model_json)
        assert list_secrets_model != False

        # Construct a model instance of ListSecrets by calling from_dict on the json representation
        list_secrets_model_dict = ListSecrets.from_dict(list_secrets_model_json).__dict__
        list_secrets_model2 = ListSecrets(**list_secrets_model_dict)

        # Verify the model instances are equivalent
        assert list_secrets_model == list_secrets_model2

        # Convert model instance back to dict and verify no loss of data
        list_secrets_model_json2 = list_secrets_model.to_dict()
        assert list_secrets_model_json2 == list_secrets_model_json


class TestSecretGroupDef():
    """
    Test Class for SecretGroupDef
    """

    def test_secret_group_def_serialization(self):
        """
        Test serialization/deserialization for SecretGroupDef
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_group_resource_model = {}  # SecretGroupResource
        secret_group_resource_model['id'] = 'bc656587-8fda-4d05-9ad8-b1de1ec7e712'
        secret_group_resource_model['name'] = 'my-secret-group'
        secret_group_resource_model['description'] = 'Extended description for this group.'
        secret_group_resource_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_group_resource_model['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_group_resource_model['type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        secret_group_resource_model['foo'] = {'foo': 'bar'}

        # Construct a json representation of a SecretGroupDef model
        secret_group_def_model_json = {}
        secret_group_def_model_json['metadata'] = collection_metadata_model
        secret_group_def_model_json['resources'] = [secret_group_resource_model]

        # Construct a model instance of SecretGroupDef by calling from_dict on the json representation
        secret_group_def_model = SecretGroupDef.from_dict(secret_group_def_model_json)
        assert secret_group_def_model != False

        # Construct a model instance of SecretGroupDef by calling from_dict on the json representation
        secret_group_def_model_dict = SecretGroupDef.from_dict(secret_group_def_model_json).__dict__
        secret_group_def_model2 = SecretGroupDef(**secret_group_def_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_def_model == secret_group_def_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_def_model_json2 = secret_group_def_model.to_dict()
        assert secret_group_def_model_json2 == secret_group_def_model_json


class TestSecretGroupMetadataUpdatable():
    """
    Test Class for SecretGroupMetadataUpdatable
    """

    def test_secret_group_metadata_updatable_serialization(self):
        """
        Test serialization/deserialization for SecretGroupMetadataUpdatable
        """

        # Construct a json representation of a SecretGroupMetadataUpdatable model
        secret_group_metadata_updatable_model_json = {}
        secret_group_metadata_updatable_model_json['name'] = 'testString'
        secret_group_metadata_updatable_model_json['description'] = 'testString'

        # Construct a model instance of SecretGroupMetadataUpdatable by calling from_dict on the json representation
        secret_group_metadata_updatable_model = SecretGroupMetadataUpdatable.from_dict(
            secret_group_metadata_updatable_model_json)
        assert secret_group_metadata_updatable_model != False

        # Construct a model instance of SecretGroupMetadataUpdatable by calling from_dict on the json representation
        secret_group_metadata_updatable_model_dict = SecretGroupMetadataUpdatable.from_dict(
            secret_group_metadata_updatable_model_json).__dict__
        secret_group_metadata_updatable_model2 = SecretGroupMetadataUpdatable(
            **secret_group_metadata_updatable_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_metadata_updatable_model == secret_group_metadata_updatable_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_metadata_updatable_model_json2 = secret_group_metadata_updatable_model.to_dict()
        assert secret_group_metadata_updatable_model_json2 == secret_group_metadata_updatable_model_json


class TestSecretGroupResource():
    """
    Test Class for SecretGroupResource
    """

    def test_secret_group_resource_serialization(self):
        """
        Test serialization/deserialization for SecretGroupResource
        """

        # Construct a json representation of a SecretGroupResource model
        secret_group_resource_model_json = {}
        secret_group_resource_model_json['id'] = 'bc656587-8fda-4d05-9ad8-b1de1ec7e712'
        secret_group_resource_model_json['name'] = 'my-secret-group'
        secret_group_resource_model_json['description'] = 'Extended description for this group.'
        secret_group_resource_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_group_resource_model_json['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_group_resource_model_json['type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        secret_group_resource_model_json['foo'] = {'foo': 'bar'}

        # Construct a model instance of SecretGroupResource by calling from_dict on the json representation
        secret_group_resource_model = SecretGroupResource.from_dict(secret_group_resource_model_json)
        assert secret_group_resource_model != False

        # Construct a model instance of SecretGroupResource by calling from_dict on the json representation
        secret_group_resource_model_dict = SecretGroupResource.from_dict(secret_group_resource_model_json).__dict__
        secret_group_resource_model2 = SecretGroupResource(**secret_group_resource_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_resource_model == secret_group_resource_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_resource_model_json2 = secret_group_resource_model.to_dict()
        assert secret_group_resource_model_json2 == secret_group_resource_model_json


class TestSecretMetadata():
    """
    Test Class for SecretMetadata
    """

    def test_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for SecretMetadata
        """

        # Construct a json representation of a SecretMetadata model
        secret_metadata_model_json = {}
        secret_metadata_model_json['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        secret_metadata_model_json['labels'] = ['dev', 'us-south']
        secret_metadata_model_json['name'] = 'example-secret'
        secret_metadata_model_json['description'] = 'Extended description for this secret.'
        secret_metadata_model_json['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        secret_metadata_model_json['state'] = 1
        secret_metadata_model_json['state_description'] = 'Active'
        secret_metadata_model_json['secret_type'] = 'arbitrary'
        secret_metadata_model_json['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model_json['ttl'] = {'foo': 'bar'}
        secret_metadata_model_json[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_metadata_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model_json['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        secret_metadata_model_json['last_update_date'] = '2020-01-28T18:40:40.123456Z'

        # Construct a model instance of SecretMetadata by calling from_dict on the json representation
        secret_metadata_model = SecretMetadata.from_dict(secret_metadata_model_json)
        assert secret_metadata_model != False

        # Construct a model instance of SecretMetadata by calling from_dict on the json representation
        secret_metadata_model_dict = SecretMetadata.from_dict(secret_metadata_model_json).__dict__
        secret_metadata_model2 = SecretMetadata(**secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert secret_metadata_model == secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        secret_metadata_model_json2 = secret_metadata_model.to_dict()
        assert secret_metadata_model_json2 == secret_metadata_model_json


class TestSecretMetadataRequest():
    """
    Test Class for SecretMetadataRequest
    """

    def test_secret_metadata_request_serialization(self):
        """
        Test serialization/deserialization for SecretMetadataRequest
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_metadata_model = {}  # SecretMetadata
        secret_metadata_model['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        secret_metadata_model['state'] = 1
        secret_metadata_model['state_description'] = 'Active'
        secret_metadata_model['secret_type'] = 'arbitrary'
        secret_metadata_model['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model['ttl'] = {'foo': 'bar'}
        secret_metadata_model[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_metadata_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_metadata_model['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        secret_metadata_model['last_update_date'] = '2020-01-28T18:40:40.123456Z'

        # Construct a json representation of a SecretMetadataRequest model
        secret_metadata_request_model_json = {}
        secret_metadata_request_model_json['metadata'] = collection_metadata_model
        secret_metadata_request_model_json['resources'] = [secret_metadata_model]

        # Construct a model instance of SecretMetadataRequest by calling from_dict on the json representation
        secret_metadata_request_model = SecretMetadataRequest.from_dict(secret_metadata_request_model_json)
        assert secret_metadata_request_model != False

        # Construct a model instance of SecretMetadataRequest by calling from_dict on the json representation
        secret_metadata_request_model_dict = SecretMetadataRequest.from_dict(
            secret_metadata_request_model_json).__dict__
        secret_metadata_request_model2 = SecretMetadataRequest(**secret_metadata_request_model_dict)

        # Verify the model instances are equivalent
        assert secret_metadata_request_model == secret_metadata_request_model2

        # Convert model instance back to dict and verify no loss of data
        secret_metadata_request_model_json2 = secret_metadata_request_model.to_dict()
        assert secret_metadata_request_model_json2 == secret_metadata_request_model_json


class TestSecretPolicyRotation():
    """
    Test Class for SecretPolicyRotation
    """

    def test_secret_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for SecretPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_policy_rotation_rotation_model = {}  # SecretPolicyRotationRotation
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a json representation of a SecretPolicyRotation model
        secret_policy_rotation_model_json = {}
        secret_policy_rotation_model_json['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        secret_policy_rotation_model_json['rotation'] = secret_policy_rotation_rotation_model

        # Construct a model instance of SecretPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_model = SecretPolicyRotation.from_dict(secret_policy_rotation_model_json)
        assert secret_policy_rotation_model != False

        # Construct a model instance of SecretPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_model_dict = SecretPolicyRotation.from_dict(secret_policy_rotation_model_json).__dict__
        secret_policy_rotation_model2 = SecretPolicyRotation(**secret_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert secret_policy_rotation_model == secret_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        secret_policy_rotation_model_json2 = secret_policy_rotation_model.to_dict()
        assert secret_policy_rotation_model_json2 == secret_policy_rotation_model_json


class TestSecretPolicyRotationRotation():
    """
    Test Class for SecretPolicyRotationRotation
    """

    def test_secret_policy_rotation_rotation_serialization(self):
        """
        Test serialization/deserialization for SecretPolicyRotationRotation
        """

        # Construct a json representation of a SecretPolicyRotationRotation model
        secret_policy_rotation_rotation_model_json = {}
        secret_policy_rotation_rotation_model_json['interval'] = 1
        secret_policy_rotation_rotation_model_json['unit'] = 'day'

        # Construct a model instance of SecretPolicyRotationRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_model = SecretPolicyRotationRotation.from_dict(
            secret_policy_rotation_rotation_model_json)
        assert secret_policy_rotation_rotation_model != False

        # Construct a model instance of SecretPolicyRotationRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_model_dict = SecretPolicyRotationRotation.from_dict(
            secret_policy_rotation_rotation_model_json).__dict__
        secret_policy_rotation_rotation_model2 = SecretPolicyRotationRotation(
            **secret_policy_rotation_rotation_model_dict)

        # Verify the model instances are equivalent
        assert secret_policy_rotation_rotation_model == secret_policy_rotation_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        secret_policy_rotation_rotation_model_json2 = secret_policy_rotation_rotation_model.to_dict()
        assert secret_policy_rotation_rotation_model_json2 == secret_policy_rotation_rotation_model_json


class TestSecretVersion():
    """
    Test Class for SecretVersion
    """

    def test_secret_version_serialization(self):
        """
        Test serialization/deserialization for SecretVersion
        """

        # Construct a json representation of a SecretVersion model
        secret_version_model_json = {}
        secret_version_model_json['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model_json['created_by'] = 'testString'
        secret_version_model_json['auto_rotated'] = True

        # Construct a model instance of SecretVersion by calling from_dict on the json representation
        secret_version_model = SecretVersion.from_dict(secret_version_model_json)
        assert secret_version_model != False

        # Construct a model instance of SecretVersion by calling from_dict on the json representation
        secret_version_model_dict = SecretVersion.from_dict(secret_version_model_json).__dict__
        secret_version_model2 = SecretVersion(**secret_version_model_dict)

        # Verify the model instances are equivalent
        assert secret_version_model == secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        secret_version_model_json2 = secret_version_model.to_dict()
        assert secret_version_model_json2 == secret_version_model_json


class TestEngineConfigOneOfIAMSecretEngineRootConfig():
    """
    Test Class for EngineConfigOneOfIAMSecretEngineRootConfig
    """

    def test_engine_config_one_of_iam_secret_engine_root_config_serialization(self):
        """
        Test serialization/deserialization for EngineConfigOneOfIAMSecretEngineRootConfig
        """

        # Construct a json representation of a EngineConfigOneOfIAMSecretEngineRootConfig model
        engine_config_one_of_iam_secret_engine_root_config_model_json = {}
        engine_config_one_of_iam_secret_engine_root_config_model_json['api_key'] = 'API_KEY'
        engine_config_one_of_iam_secret_engine_root_config_model_json[
            'api_key_hash'] = 'a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91'

        # Construct a model instance of EngineConfigOneOfIAMSecretEngineRootConfig by calling from_dict on the json representation
        engine_config_one_of_iam_secret_engine_root_config_model = EngineConfigOneOfIAMSecretEngineRootConfig.from_dict(
            engine_config_one_of_iam_secret_engine_root_config_model_json)
        assert engine_config_one_of_iam_secret_engine_root_config_model != False

        # Construct a model instance of EngineConfigOneOfIAMSecretEngineRootConfig by calling from_dict on the json representation
        engine_config_one_of_iam_secret_engine_root_config_model_dict = EngineConfigOneOfIAMSecretEngineRootConfig.from_dict(
            engine_config_one_of_iam_secret_engine_root_config_model_json).__dict__
        engine_config_one_of_iam_secret_engine_root_config_model2 = EngineConfigOneOfIAMSecretEngineRootConfig(
            **engine_config_one_of_iam_secret_engine_root_config_model_dict)

        # Verify the model instances are equivalent
        assert engine_config_one_of_iam_secret_engine_root_config_model == engine_config_one_of_iam_secret_engine_root_config_model2

        # Convert model instance back to dict and verify no loss of data
        engine_config_one_of_iam_secret_engine_root_config_model_json2 = engine_config_one_of_iam_secret_engine_root_config_model.to_dict()
        assert engine_config_one_of_iam_secret_engine_root_config_model_json2 == engine_config_one_of_iam_secret_engine_root_config_model_json


class TestGetSecretPoliciesOneOfGetSecretPolicyRotation():
    """
    Test Class for GetSecretPoliciesOneOfGetSecretPolicyRotation
    """

    def test_get_secret_policies_one_of_get_secret_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for GetSecretPoliciesOneOfGetSecretPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {}  # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.secret+json'
        collection_metadata_model['collection_total'] = 1

        secret_policy_rotation_rotation_model = {}  # SecretPolicyRotationRotation
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model = {}  # GetSecretPoliciesOneOfGetSecretPolicyRotationResourcesItem
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model['id'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model[
            'crn'] = 'crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model[
            'creation_date'] = '2020-01-28T18:40:40.123456Z'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model['created_by'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model[
            'last_update_date'] = '2020-01-28T18:40:40.123456Z'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model['updated_by'] = 'testString'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model[
            'type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model[
            'rotation'] = secret_policy_rotation_rotation_model

        # Construct a json representation of a GetSecretPoliciesOneOfGetSecretPolicyRotation model
        get_secret_policies_one_of_get_secret_policy_rotation_model_json = {}
        get_secret_policies_one_of_get_secret_policy_rotation_model_json['metadata'] = collection_metadata_model
        get_secret_policies_one_of_get_secret_policy_rotation_model_json['resources'] = [
            get_secret_policies_one_of_get_secret_policy_rotation_resources_item_model]

        # Construct a model instance of GetSecretPoliciesOneOfGetSecretPolicyRotation by calling from_dict on the json representation
        get_secret_policies_one_of_get_secret_policy_rotation_model = GetSecretPoliciesOneOfGetSecretPolicyRotation.from_dict(
            get_secret_policies_one_of_get_secret_policy_rotation_model_json)
        assert get_secret_policies_one_of_get_secret_policy_rotation_model != False

        # Construct a model instance of GetSecretPoliciesOneOfGetSecretPolicyRotation by calling from_dict on the json representation
        get_secret_policies_one_of_get_secret_policy_rotation_model_dict = GetSecretPoliciesOneOfGetSecretPolicyRotation.from_dict(
            get_secret_policies_one_of_get_secret_policy_rotation_model_json).__dict__
        get_secret_policies_one_of_get_secret_policy_rotation_model2 = GetSecretPoliciesOneOfGetSecretPolicyRotation(
            **get_secret_policies_one_of_get_secret_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_policies_one_of_get_secret_policy_rotation_model == get_secret_policies_one_of_get_secret_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_policies_one_of_get_secret_policy_rotation_model_json2 = get_secret_policies_one_of_get_secret_policy_rotation_model.to_dict()
        assert get_secret_policies_one_of_get_secret_policy_rotation_model_json2 == get_secret_policies_one_of_get_secret_policy_rotation_model_json


class TestSecretActionOneOfDeleteCredentialsForIAMSecret():
    """
    Test Class for SecretActionOneOfDeleteCredentialsForIAMSecret
    """

    def test_secret_action_one_of_delete_credentials_for_iam_secret_serialization(self):
        """
        Test serialization/deserialization for SecretActionOneOfDeleteCredentialsForIAMSecret
        """

        # Construct a json representation of a SecretActionOneOfDeleteCredentialsForIAMSecret model
        secret_action_one_of_delete_credentials_for_iam_secret_model_json = {}
        secret_action_one_of_delete_credentials_for_iam_secret_model_json['service_id'] = 'testString'

        # Construct a model instance of SecretActionOneOfDeleteCredentialsForIAMSecret by calling from_dict on the json representation
        secret_action_one_of_delete_credentials_for_iam_secret_model = SecretActionOneOfDeleteCredentialsForIAMSecret.from_dict(
            secret_action_one_of_delete_credentials_for_iam_secret_model_json)
        assert secret_action_one_of_delete_credentials_for_iam_secret_model != False

        # Construct a model instance of SecretActionOneOfDeleteCredentialsForIAMSecret by calling from_dict on the json representation
        secret_action_one_of_delete_credentials_for_iam_secret_model_dict = SecretActionOneOfDeleteCredentialsForIAMSecret.from_dict(
            secret_action_one_of_delete_credentials_for_iam_secret_model_json).__dict__
        secret_action_one_of_delete_credentials_for_iam_secret_model2 = SecretActionOneOfDeleteCredentialsForIAMSecret(
            **secret_action_one_of_delete_credentials_for_iam_secret_model_dict)

        # Verify the model instances are equivalent
        assert secret_action_one_of_delete_credentials_for_iam_secret_model == secret_action_one_of_delete_credentials_for_iam_secret_model2

        # Convert model instance back to dict and verify no loss of data
        secret_action_one_of_delete_credentials_for_iam_secret_model_json2 = secret_action_one_of_delete_credentials_for_iam_secret_model.to_dict()
        assert secret_action_one_of_delete_credentials_for_iam_secret_model_json2 == secret_action_one_of_delete_credentials_for_iam_secret_model_json


class TestSecretActionOneOfRotateArbitrarySecretBody():
    """
    Test Class for SecretActionOneOfRotateArbitrarySecretBody
    """

    def test_secret_action_one_of_rotate_arbitrary_secret_body_serialization(self):
        """
        Test serialization/deserialization for SecretActionOneOfRotateArbitrarySecretBody
        """

        # Construct a json representation of a SecretActionOneOfRotateArbitrarySecretBody model
        secret_action_one_of_rotate_arbitrary_secret_body_model_json = {}
        secret_action_one_of_rotate_arbitrary_secret_body_model_json['payload'] = 'testString'

        # Construct a model instance of SecretActionOneOfRotateArbitrarySecretBody by calling from_dict on the json representation
        secret_action_one_of_rotate_arbitrary_secret_body_model = SecretActionOneOfRotateArbitrarySecretBody.from_dict(
            secret_action_one_of_rotate_arbitrary_secret_body_model_json)
        assert secret_action_one_of_rotate_arbitrary_secret_body_model != False

        # Construct a model instance of SecretActionOneOfRotateArbitrarySecretBody by calling from_dict on the json representation
        secret_action_one_of_rotate_arbitrary_secret_body_model_dict = SecretActionOneOfRotateArbitrarySecretBody.from_dict(
            secret_action_one_of_rotate_arbitrary_secret_body_model_json).__dict__
        secret_action_one_of_rotate_arbitrary_secret_body_model2 = SecretActionOneOfRotateArbitrarySecretBody(
            **secret_action_one_of_rotate_arbitrary_secret_body_model_dict)

        # Verify the model instances are equivalent
        assert secret_action_one_of_rotate_arbitrary_secret_body_model == secret_action_one_of_rotate_arbitrary_secret_body_model2

        # Convert model instance back to dict and verify no loss of data
        secret_action_one_of_rotate_arbitrary_secret_body_model_json2 = secret_action_one_of_rotate_arbitrary_secret_body_model.to_dict()
        assert secret_action_one_of_rotate_arbitrary_secret_body_model_json2 == secret_action_one_of_rotate_arbitrary_secret_body_model_json


class TestSecretActionOneOfRotateUsernamePasswordSecretBody():
    """
    Test Class for SecretActionOneOfRotateUsernamePasswordSecretBody
    """

    def test_secret_action_one_of_rotate_username_password_secret_body_serialization(self):
        """
        Test serialization/deserialization for SecretActionOneOfRotateUsernamePasswordSecretBody
        """

        # Construct a json representation of a SecretActionOneOfRotateUsernamePasswordSecretBody model
        secret_action_one_of_rotate_username_password_secret_body_model_json = {}
        secret_action_one_of_rotate_username_password_secret_body_model_json['password'] = 'testString'

        # Construct a model instance of SecretActionOneOfRotateUsernamePasswordSecretBody by calling from_dict on the json representation
        secret_action_one_of_rotate_username_password_secret_body_model = SecretActionOneOfRotateUsernamePasswordSecretBody.from_dict(
            secret_action_one_of_rotate_username_password_secret_body_model_json)
        assert secret_action_one_of_rotate_username_password_secret_body_model != False

        # Construct a model instance of SecretActionOneOfRotateUsernamePasswordSecretBody by calling from_dict on the json representation
        secret_action_one_of_rotate_username_password_secret_body_model_dict = SecretActionOneOfRotateUsernamePasswordSecretBody.from_dict(
            secret_action_one_of_rotate_username_password_secret_body_model_json).__dict__
        secret_action_one_of_rotate_username_password_secret_body_model2 = SecretActionOneOfRotateUsernamePasswordSecretBody(
            **secret_action_one_of_rotate_username_password_secret_body_model_dict)

        # Verify the model instances are equivalent
        assert secret_action_one_of_rotate_username_password_secret_body_model == secret_action_one_of_rotate_username_password_secret_body_model2

        # Convert model instance back to dict and verify no loss of data
        secret_action_one_of_rotate_username_password_secret_body_model_json2 = secret_action_one_of_rotate_username_password_secret_body_model.to_dict()
        assert secret_action_one_of_rotate_username_password_secret_body_model_json2 == secret_action_one_of_rotate_username_password_secret_body_model_json


class TestSecretResourceArbitrarySecretResource():
    """
    Test Class for SecretResourceArbitrarySecretResource
    """

    def test_secret_resource_arbitrary_secret_resource_serialization(self):
        """
        Test serialization/deserialization for SecretResourceArbitrarySecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        # Construct a json representation of a SecretResourceArbitrarySecretResource model
        secret_resource_arbitrary_secret_resource_model_json = {}
        secret_resource_arbitrary_secret_resource_model_json['type'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['id'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['name'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['description'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['secret_group_id'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['labels'] = ['testString']
        secret_resource_arbitrary_secret_resource_model_json['state'] = 0
        secret_resource_arbitrary_secret_resource_model_json['state_description'] = 'Active'
        secret_resource_arbitrary_secret_resource_model_json['secret_type'] = 'arbitrary'
        secret_resource_arbitrary_secret_resource_model_json[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_arbitrary_secret_resource_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_arbitrary_secret_resource_model_json['created_by'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_arbitrary_secret_resource_model_json['versions'] = [secret_version_model]
        secret_resource_arbitrary_secret_resource_model_json['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_arbitrary_secret_resource_model_json['payload'] = 'testString'
        secret_resource_arbitrary_secret_resource_model_json['secret_data'] = {'foo': 'bar'}

        # Construct a model instance of SecretResourceArbitrarySecretResource by calling from_dict on the json representation
        secret_resource_arbitrary_secret_resource_model = SecretResourceArbitrarySecretResource.from_dict(
            secret_resource_arbitrary_secret_resource_model_json)
        assert secret_resource_arbitrary_secret_resource_model != False

        # Construct a model instance of SecretResourceArbitrarySecretResource by calling from_dict on the json representation
        secret_resource_arbitrary_secret_resource_model_dict = SecretResourceArbitrarySecretResource.from_dict(
            secret_resource_arbitrary_secret_resource_model_json).__dict__
        secret_resource_arbitrary_secret_resource_model2 = SecretResourceArbitrarySecretResource(
            **secret_resource_arbitrary_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert secret_resource_arbitrary_secret_resource_model == secret_resource_arbitrary_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        secret_resource_arbitrary_secret_resource_model_json2 = secret_resource_arbitrary_secret_resource_model.to_dict()
        assert secret_resource_arbitrary_secret_resource_model_json2 == secret_resource_arbitrary_secret_resource_model_json


class TestSecretResourceIAMSecretResource():
    """
    Test Class for SecretResourceIAMSecretResource
    """

    def test_secret_resource_iam_secret_resource_serialization(self):
        """
        Test serialization/deserialization for SecretResourceIAMSecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        # Construct a json representation of a SecretResourceIAMSecretResource model
        secret_resource_iam_secret_resource_model_json = {}
        secret_resource_iam_secret_resource_model_json['type'] = 'testString'
        secret_resource_iam_secret_resource_model_json['id'] = 'testString'
        secret_resource_iam_secret_resource_model_json['name'] = 'testString'
        secret_resource_iam_secret_resource_model_json['description'] = 'testString'
        secret_resource_iam_secret_resource_model_json['secret_group_id'] = 'testString'
        secret_resource_iam_secret_resource_model_json['labels'] = ['testString']
        secret_resource_iam_secret_resource_model_json['state'] = 0
        secret_resource_iam_secret_resource_model_json['state_description'] = 'Active'
        secret_resource_iam_secret_resource_model_json['secret_type'] = 'arbitrary'
        secret_resource_iam_secret_resource_model_json[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_iam_secret_resource_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_iam_secret_resource_model_json['created_by'] = 'testString'
        secret_resource_iam_secret_resource_model_json['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_iam_secret_resource_model_json['versions'] = [secret_version_model]
        secret_resource_iam_secret_resource_model_json['ttl'] = {'foo': 'bar'}
        secret_resource_iam_secret_resource_model_json['access_groups'] = [
            'AccessGroupId-45884031-54be-4dd7-86ff-112511e92699', 'AccessGroupId-2c190fb5-0d9d-46c5-acf3-78ecd30e24a0']
        secret_resource_iam_secret_resource_model_json['api_key'] = 'testString'
        secret_resource_iam_secret_resource_model_json['service_id'] = 'testString'
        secret_resource_iam_secret_resource_model_json['reuse_api_key'] = True

        # Construct a model instance of SecretResourceIAMSecretResource by calling from_dict on the json representation
        secret_resource_iam_secret_resource_model = SecretResourceIAMSecretResource.from_dict(
            secret_resource_iam_secret_resource_model_json)
        assert secret_resource_iam_secret_resource_model != False

        # Construct a model instance of SecretResourceIAMSecretResource by calling from_dict on the json representation
        secret_resource_iam_secret_resource_model_dict = SecretResourceIAMSecretResource.from_dict(
            secret_resource_iam_secret_resource_model_json).__dict__
        secret_resource_iam_secret_resource_model2 = SecretResourceIAMSecretResource(
            **secret_resource_iam_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert secret_resource_iam_secret_resource_model == secret_resource_iam_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        secret_resource_iam_secret_resource_model_json2 = secret_resource_iam_secret_resource_model.to_dict()
        assert secret_resource_iam_secret_resource_model_json2 == secret_resource_iam_secret_resource_model_json


class TestSecretResourceUsernamePasswordSecretResource():
    """
    Test Class for SecretResourceUsernamePasswordSecretResource
    """

    def test_secret_resource_username_password_secret_resource_serialization(self):
        """
        Test serialization/deserialization for SecretResourceUsernamePasswordSecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_version_model = {}  # SecretVersion
        secret_version_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_version_model['created_by'] = 'testString'
        secret_version_model['auto_rotated'] = True

        # Construct a json representation of a SecretResourceUsernamePasswordSecretResource model
        secret_resource_username_password_secret_resource_model_json = {}
        secret_resource_username_password_secret_resource_model_json['type'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['id'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['name'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['description'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['secret_group_id'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['labels'] = ['testString']
        secret_resource_username_password_secret_resource_model_json['state'] = 0
        secret_resource_username_password_secret_resource_model_json['state_description'] = 'Active'
        secret_resource_username_password_secret_resource_model_json['secret_type'] = 'arbitrary'
        secret_resource_username_password_secret_resource_model_json[
            'crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_username_password_secret_resource_model_json['creation_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_username_password_secret_resource_model_json['created_by'] = 'testString'
        secret_resource_username_password_secret_resource_model_json['last_update_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_username_password_secret_resource_model_json['versions'] = [secret_version_model]
        secret_resource_username_password_secret_resource_model_json['username'] = 'user123'
        secret_resource_username_password_secret_resource_model_json['password'] = 'rainy-cloudy-coffee-book'
        secret_resource_username_password_secret_resource_model_json['secret_data'] = {'foo': 'bar'}
        secret_resource_username_password_secret_resource_model_json['expiration_date'] = '2020-01-28T18:40:40.123456Z'
        secret_resource_username_password_secret_resource_model_json[
            'next_rotation_date'] = '2020-01-28T18:40:40.123456Z'

        # Construct a model instance of SecretResourceUsernamePasswordSecretResource by calling from_dict on the json representation
        secret_resource_username_password_secret_resource_model = SecretResourceUsernamePasswordSecretResource.from_dict(
            secret_resource_username_password_secret_resource_model_json)
        assert secret_resource_username_password_secret_resource_model != False

        # Construct a model instance of SecretResourceUsernamePasswordSecretResource by calling from_dict on the json representation
        secret_resource_username_password_secret_resource_model_dict = SecretResourceUsernamePasswordSecretResource.from_dict(
            secret_resource_username_password_secret_resource_model_json).__dict__
        secret_resource_username_password_secret_resource_model2 = SecretResourceUsernamePasswordSecretResource(
            **secret_resource_username_password_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert secret_resource_username_password_secret_resource_model == secret_resource_username_password_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        secret_resource_username_password_secret_resource_model_json2 = secret_resource_username_password_secret_resource_model.to_dict()
        assert secret_resource_username_password_secret_resource_model_json2 == secret_resource_username_password_secret_resource_model_json

# endregion
##############################################################################
# End of Model Tests
##############################################################################
