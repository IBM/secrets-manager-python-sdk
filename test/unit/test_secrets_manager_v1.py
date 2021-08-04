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
from ibm_cloud_sdk_core.utils import datetime_to_string, string_to_datetime
import inspect
import json
import os
import pytest
import re
import requests
import responses
import urllib
from ibm_secrets_manager_sdk.secrets_manager_v1 import *


_service = SecretsManagerV1(
    authenticator=NoAuthAuthenticator()
    )

_base_url = 'https://secrets-manager.cloud.ibm.com'
_service.set_service_url(_base_url)

##############################################################################
# Start of Service: Config
##############################################################################
# region

class TestNewInstance():
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV1.new_instance(
            )

class TestCreateSecretConfigElement():
    """
    Test Class for create_secret_config_element
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_create_secret_config_element_all_params(self):
        """
        create_secret_config_element()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        name = 'testString'
        type = 'testString'
        config = { 'foo': 'bar' }

        # Invoke method
        response = _service.create_secret_config_element(
            secret_type,
            config_element,
            name,
            type,
            config,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 201
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['name'] == 'testString'
        assert req_body['type'] == 'testString'
        assert req_body['config'] == { 'foo': 'bar' }


    @responses.activate
    def test_create_secret_config_element_value_error(self):
        """
        test_create_secret_config_element_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        name = 'testString'
        type = 'testString'
        config = { 'foo': 'bar' }

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "config_element": config_element,
            "name": name,
            "type": type,
            "config": config,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_config_element(**req_copy)



class TestGetSecretConfigElement():
    """
    Test Class for get_secret_config_element
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_config_element_all_params(self):
        """
        get_secret_config_element()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "name", "type": "type"}]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'

        # Invoke method
        response = _service.get_secret_config_element(
            secret_type,
            config_element,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    @responses.activate
    def test_get_secret_config_element_value_error(self):
        """
        test_get_secret_config_element_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "name", "type": "type"}]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "config_element": config_element,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_config_element(**req_copy)



class TestUpdateSecretConfigElement():
    """
    Test Class for update_secret_config_element
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_update_secret_config_element_all_params(self):
        """
        update_secret_config_element()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'
        type = 'testString'
        config = { 'foo': 'bar' }

        # Invoke method
        response = _service.update_secret_config_element(
            secret_type,
            config_element,
            config_name,
            type,
            config,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['type'] == 'testString'
        assert req_body['config'] == { 'foo': 'bar' }


    @responses.activate
    def test_update_secret_config_element_value_error(self):
        """
        test_update_secret_config_element_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'
        type = 'testString'
        config = { 'foo': 'bar' }

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "config_element": config_element,
            "config_name": config_name,
            "type": type,
            "config": config,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_config_element(**req_copy)



class TestDeleteSecretConfigElement():
    """
    Test Class for delete_secret_config_element
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_delete_secret_config_element_all_params(self):
        """
        delete_secret_config_element()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'

        # Invoke method
        response = _service.delete_secret_config_element(
            secret_type,
            config_element,
            config_name,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204


    @responses.activate
    def test_delete_secret_config_element_value_error(self):
        """
        test_delete_secret_config_element_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "config_element": config_element,
            "config_name": config_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_config_element(**req_copy)



class TestGetSingleSecretConfigElement():
    """
    Test Class for get_single_secret_config_element
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_single_secret_config_element_all_params(self):
        """
        get_single_secret_config_element()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'

        # Invoke method
        response = _service.get_single_secret_config_element(
            secret_type,
            config_element,
            config_name,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    @responses.activate
    def test_get_single_secret_config_element_value_error(self):
        """
        test_get_single_secret_config_element_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/public_cert/certificate_authorities/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"name": "name", "type": "type", "config": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'public_cert'
        config_element = 'certificate_authorities'
        config_name = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "config_element": config_element,
            "config_name": config_name,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_single_secret_config_element(**req_copy)



class TestPutConfig():
    """
    Test Class for put_config
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/config/iam_credentials')
        responses.add(responses.PUT,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'iam_credentials'
        api_key = 'API_KEY'

        # Invoke method
        response = _service.put_config(
            secret_type,
            api_key,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 204
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['api_key'] == 'API_KEY'


    @responses.activate
    def test_put_config_value_error(self):
        """
        test_put_config_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/config/iam_credentials')
        responses.add(responses.PUT,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'iam_credentials'
        api_key = 'API_KEY'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "api_key": api_key,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.put_config(**req_copy)



class TestGetConfig():
    """
    Test Class for get_config
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/config/iam_credentials')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "name", "type": "type"}], "dns_providers": [{"name": "name", "type": "type"}]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'iam_credentials'

        # Invoke method
        response = _service.get_config(
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
        url = self.preprocess_url(_base_url + '/api/v1/config/iam_credentials')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"certificate_authorities": [{"name": "name", "type": "type"}], "dns_providers": [{"name": "name", "type": "type"}]}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_config(**req_copy)



# endregion
##############################################################################
# End of Service: Config
##############################################################################

##############################################################################
# Start of Service: Policies
##############################################################################
# region

class TestNewInstance():
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV1.new_instance(
            )

class TestPutPolicy():
    """
    Test Class for put_policy
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotationPolicyRotation model
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
        response = _service.put_policy(
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
        query_string = responses.calls[0].request.url.split('?',1)[1]
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotationPolicyRotation model
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
        response = _service.put_policy(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a SecretPolicyRotationRotationPolicyRotation model
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.put_policy(**req_copy)



class TestGetPolicy():
    """
    Test Class for get_policy
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
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
        response = _service.get_policy(
            secret_type,
            id,
            policy=policy,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'policy={}'.format(policy) in query_string


    @responses.activate
    def test_get_policy_required_params(self):
        """
        test_get_policy_required_params()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'username_password'
        id = 'testString'

        # Invoke method
        response = _service.get_policy(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/username_password/testString/policies')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "last_update_date": "2019-01-01T12:00:00.000Z", "updated_by": "updated_by", "type": "application/vnd.ibm.secrets-manager.secret.policy+json", "rotation": {"interval": 1, "unit": "day"}}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_policy(**req_copy)



# endregion
##############################################################################
# End of Service: Policies
##############################################################################

##############################################################################
# Start of Service: SecretGroups
##############################################################################
# region

class TestNewInstance():
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV1.new_instance(
            )

class TestCreateSecretGroup():
    """
    Test Class for create_secret_group
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
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
        secret_group_resource_model['foo'] = 'testString'

        # Set up parameter values
        metadata = collection_metadata_model
        resources = [secret_group_resource_model]

        # Invoke method
        response = _service.create_secret_group(
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
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
        secret_group_resource_model['foo'] = 'testString'

        # Set up parameter values
        metadata = collection_metadata_model
        resources = [secret_group_resource_model]

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "metadata": metadata,
            "resources": resources,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret_group(**req_copy)



class TestListSecretGroups():
    """
    Test Class for list_secret_groups
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = _service.list_secret_groups()


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
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = _service.get_secret_group(
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_group(**req_copy)



class TestUpdateSecretGroupMetadata():
    """
    Test Class for update_secret_group_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
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
        response = _service.update_secret_group_metadata(
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "bc656587-8fda-4d05-9ad8-b1de1ec7e712", "name": "my-secret-group", "description": "Extended description for this group.", "creation_date": "2018-04-12T23:20:50.520Z", "last_update_date": "2018-05-12T23:20:50.520Z", "type": "application/vnd.ibm.secrets-manager.secret.group+json"}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_group_metadata(**req_copy)



class TestDeleteSecretGroup():
    """
    Test Class for delete_secret_group
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = _service.delete_secret_group(
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
        url = self.preprocess_url(_base_url + '/api/v1/secret_groups/testString')
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret_group(**req_copy)



# endregion
##############################################################################
# End of Service: SecretGroups
##############################################################################

##############################################################################
# Start of Service: Secrets
##############################################################################
# region

class TestNewInstance():
    """
    Test Class for new_instance
    """

    def test_new_instance(self):
        """
        new_instance()
        """
        os.environ['TEST_SERVICE_AUTH_TYPE'] = 'noAuth'

        service = SecretsManagerV1.new_instance(
            service_name='TEST_SERVICE',
        )

        assert service is not None
        assert isinstance(service, SecretsManagerV1)

    def test_new_instance_without_authenticator(self):
        """
        new_instance_without_authenticator()
        """
        with pytest.raises(ValueError, match='authenticator must be provided'):
            service = SecretsManagerV1.new_instance(
            )

class TestCreateSecret():
    """
    Test Class for create_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a ArbitrarySecretResource model
        secret_resource_model = {}
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['expiration_date'] = "2030-04-01T09:30:00Z"
        secret_resource_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        metadata = collection_metadata_model
        resources = [secret_resource_model]

        # Invoke method
        response = _service.create_secret(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=201)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a ArbitrarySecretResource model
        secret_resource_model = {}
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['expiration_date'] = "2030-04-01T09:30:00Z"
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.create_secret(**req_copy)



class TestListSecrets():
    """
    Test Class for list_secrets
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
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
        response = _service.list_secrets(
            secret_type,
            limit=limit,
            offset=offset,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'limit={}'.format(limit) in query_string
        assert 'offset={}'.format(offset) in query_string


    @responses.activate
    def test_list_secrets_required_params(self):
        """
        test_list_secrets_required_params()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'

        # Invoke method
        response = _service.list_secrets(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.list_secrets(**req_copy)



class TestListAllSecrets():
    """
    Test Class for list_all_secrets
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
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
        groups = ['testString']

        # Invoke method
        response = _service.list_all_secrets(
            limit=limit,
            offset=offset,
            search=search,
            sort_by=sort_by,
            groups=groups,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'limit={}'.format(limit) in query_string
        assert 'offset={}'.format(offset) in query_string
        assert 'search={}'.format(search) in query_string
        assert 'sort_by={}'.format(sort_by) in query_string
        assert 'groups={}'.format(','.join(groups)) in query_string


    @responses.activate
    def test_list_all_secrets_required_params(self):
        """
        test_list_all_secrets_required_params()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = _service.list_all_secrets()


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
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = _service.get_secret(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret(**req_copy)



class TestUpdateSecret():
    """
    Test Class for update_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a RotateArbitrarySecretBody model
        secret_action_model = {}
        secret_action_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        action = 'rotate'
        secret_action = secret_action_model

        # Invoke method
        response = _service.update_secret(
            secret_type,
            id,
            action,
            secret_action,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = urllib.parse.unquote_plus(query_string)
        assert 'action={}'.format(action) in query_string
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body == secret_action


    @responses.activate
    def test_update_secret_value_error(self):
        """
        test_update_secret_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "name": "name", "description": "description", "secret_group_id": "secret_group_id", "labels": ["labels"], "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "created_by", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "versions": [{"mapKey": "anyValue"}], "expiration_date": "2030-04-01T09:30:00.000Z", "payload": "payload", "secret_data": {"anyKey": "anyValue"}}]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a RotateArbitrarySecretBody model
        secret_action_model = {}
        secret_action_model['payload'] = 'testString'

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        action = 'rotate'
        secret_action = secret_action_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "action": action,
            "secret_action": secret_action,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret(**req_copy)



class TestDeleteSecret():
    """
    Test Class for delete_secret
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
        responses.add(responses.DELETE,
                      url,
                      status=204)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = _service.delete_secret(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString')
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.delete_secret(**req_copy)



class TestGetSecretVersion():
    """
    Test Class for get_secret_version
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_version_all_params(self):
        """
        get_secret_version()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/imported_cert/testString/versions/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "validity": {"not_before": "2020-10-05T21:33:11.000Z", "not_after": "2021-01-01T00:00:00.000Z"}, "serial_number": "serial_number", "expiration_date": "2030-04-01T09:30:00.000Z", "secret_data": {"certificate": "certificate", "private_key": "private_key", "intermediate": "intermediate"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'imported_cert'
        id = 'testString'
        version_id = 'testString'

        # Invoke method
        response = _service.get_secret_version(
            secret_type,
            id,
            version_id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    @responses.activate
    def test_get_secret_version_value_error(self):
        """
        test_get_secret_version_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/imported_cert/testString/versions/testString')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "id", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "version_id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by", "validity": {"not_before": "2020-10-05T21:33:11.000Z", "not_after": "2021-01-01T00:00:00.000Z"}, "serial_number": "serial_number", "expiration_date": "2030-04-01T09:30:00.000Z", "secret_data": {"certificate": "certificate", "private_key": "private_key", "intermediate": "intermediate"}}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'imported_cert'
        id = 'testString'
        version_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "version_id": version_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_version(**req_copy)



class TestGetSecretVersionMetadata():
    """
    Test Class for get_secret_version_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    @responses.activate
    def test_get_secret_version_metadata_all_params(self):
        """
        get_secret_version_metadata()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/imported_cert/testString/versions/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'imported_cert'
        id = 'testString'
        version_id = 'testString'

        # Invoke method
        response = _service.get_secret_version_metadata(
            secret_type,
            id,
            version_id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    @responses.activate
    def test_get_secret_version_metadata_value_error(self):
        """
        test_get_secret_version_metadata_value_error()
        """
        # Set up mock
        url = self.preprocess_url(_base_url + '/api/v1/secrets/imported_cert/testString/versions/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "4a0225e9-17a0-46c1-ace7-f25bcf4237d4", "creation_date": "2019-01-01T12:00:00.000Z", "created_by": "created_by"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'imported_cert'
        id = 'testString'
        version_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "secret_type": secret_type,
            "id": id,
            "version_id": version_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_version_metadata(**req_copy)



class TestGetSecretMetadata():
    """
    Test Class for get_secret_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "expiration_date": "2030-04-01T09:30:00.000Z"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'

        # Invoke method
        response = _service.get_secret_metadata(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "expiration_date": "2030-04-01T09:30:00.000Z"}]}'
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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.get_secret_metadata(**req_copy)



class TestUpdateSecretMetadata():
    """
    Test Class for update_secret_metadata
    """

    def preprocess_url(self, request_url: str):
        """
        Preprocess the request URL to ensure the mock response will be found.
        """
        request_url = urllib.parse.unquote(request_url) # don't double-encode if already encoded
        request_url = urllib.parse.quote(request_url, safe=':/')
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "expiration_date": "2030-04-01T09:30:00.000Z"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a ArbitrarySecretMetadata model
        secret_metadata_model = {}
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['expiration_date'] = "2030-04-01T09:30:00Z"

        # Set up parameter values
        secret_type = 'arbitrary'
        id = 'testString'
        metadata = collection_metadata_model
        resources = [secret_metadata_model]

        # Invoke method
        response = _service.update_secret_metadata(
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
        url = self.preprocess_url(_base_url + '/api/v1/secrets/arbitrary/testString/metadata')
        mock_response = '{"metadata": {"collection_type": "application/vnd.ibm.secrets-manager.config+json", "collection_total": 1}, "resources": [{"id": "b0283d74-0894-830b-f81d-1f115f67729f", "labels": ["labels"], "name": "example-secret", "description": "Extended description for this secret.", "secret_group_id": "f5283d74-9024-230a-b72c-1f115f61290f", "state": 0, "state_description": "Active", "secret_type": "arbitrary", "crn": "crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>", "creation_date": "2018-04-12T23:20:50.520Z", "created_by": "ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976", "last_update_date": "2018-04-12T23:20:50.520Z", "versions_total": 1, "expiration_date": "2030-04-01T09:30:00.000Z"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a CollectionMetadata model
        collection_metadata_model = {}
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        # Construct a dict representation of a ArbitrarySecretMetadata model
        secret_metadata_model = {}
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['expiration_date'] = "2030-04-01T09:30:00Z"

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
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                _service.update_secret_metadata(**req_copy)



# endregion
##############################################################################
# End of Service: Secrets
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region
class TestModel_CertificateSecretData():
    """
    Test Class for CertificateSecretData
    """

    def test_certificate_secret_data_serialization(self):
        """
        Test serialization/deserialization for CertificateSecretData
        """

        # Construct a json representation of a CertificateSecretData model
        certificate_secret_data_model_json = {}
        certificate_secret_data_model_json['certificate'] = 'testString'
        certificate_secret_data_model_json['private_key'] = 'testString'
        certificate_secret_data_model_json['intermediate'] = 'testString'

        # Construct a model instance of CertificateSecretData by calling from_dict on the json representation
        certificate_secret_data_model = CertificateSecretData.from_dict(certificate_secret_data_model_json)
        assert certificate_secret_data_model != False

        # Construct a model instance of CertificateSecretData by calling from_dict on the json representation
        certificate_secret_data_model_dict = CertificateSecretData.from_dict(certificate_secret_data_model_json).__dict__
        certificate_secret_data_model2 = CertificateSecretData(**certificate_secret_data_model_dict)

        # Verify the model instances are equivalent
        assert certificate_secret_data_model == certificate_secret_data_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_secret_data_model_json2 = certificate_secret_data_model.to_dict()
        assert certificate_secret_data_model_json2 == certificate_secret_data_model_json

class TestModel_CollectionMetadata():
    """
    Test Class for CollectionMetadata
    """

    def test_collection_metadata_serialization(self):
        """
        Test serialization/deserialization for CollectionMetadata
        """

        # Construct a json representation of a CollectionMetadata model
        collection_metadata_model_json = {}
        collection_metadata_model_json['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
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

class TestModel_ConfigElement():
    """
    Test Class for ConfigElement
    """

    def test_config_element_serialization(self):
        """
        Test serialization/deserialization for ConfigElement
        """

        # Construct a json representation of a ConfigElement model
        config_element_model_json = {}
        config_element_model_json['name'] = 'testString'
        config_element_model_json['type'] = 'testString'
        config_element_model_json['config'] = { 'foo': 'bar' }

        # Construct a model instance of ConfigElement by calling from_dict on the json representation
        config_element_model = ConfigElement.from_dict(config_element_model_json)
        assert config_element_model != False

        # Construct a model instance of ConfigElement by calling from_dict on the json representation
        config_element_model_dict = ConfigElement.from_dict(config_element_model_json).__dict__
        config_element_model2 = ConfigElement(**config_element_model_dict)

        # Verify the model instances are equivalent
        assert config_element_model == config_element_model2

        # Convert model instance back to dict and verify no loss of data
        config_element_model_json2 = config_element_model.to_dict()
        assert config_element_model_json2 == config_element_model_json

class TestModel_ConfigElementMetadata():
    """
    Test Class for ConfigElementMetadata
    """

    def test_config_element_metadata_serialization(self):
        """
        Test serialization/deserialization for ConfigElementMetadata
        """

        # Construct a json representation of a ConfigElementMetadata model
        config_element_metadata_model_json = {}
        config_element_metadata_model_json['name'] = 'testString'
        config_element_metadata_model_json['type'] = 'testString'

        # Construct a model instance of ConfigElementMetadata by calling from_dict on the json representation
        config_element_metadata_model = ConfigElementMetadata.from_dict(config_element_metadata_model_json)
        assert config_element_metadata_model != False

        # Construct a model instance of ConfigElementMetadata by calling from_dict on the json representation
        config_element_metadata_model_dict = ConfigElementMetadata.from_dict(config_element_metadata_model_json).__dict__
        config_element_metadata_model2 = ConfigElementMetadata(**config_element_metadata_model_dict)

        # Verify the model instances are equivalent
        assert config_element_metadata_model == config_element_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        config_element_metadata_model_json2 = config_element_metadata_model.to_dict()
        assert config_element_metadata_model_json2 == config_element_metadata_model_json

class TestModel_CreateSecret():
    """
    Test Class for CreateSecret
    """

    def test_create_secret_serialization(self):
        """
        Test serialization/deserialization for CreateSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_resource_model = {} # ArbitrarySecretResource
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['versions_total'] = 1
        secret_resource_model['versions'] = [{}]
        secret_resource_model['expiration_date'] = "2030-04-01T09:30:00Z"
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = { 'foo': 'bar' }

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

class TestModel_GetConfig():
    """
    Test Class for GetConfig
    """

    def test_get_config_serialization(self):
        """
        Test serialization/deserialization for GetConfig
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        config_element_metadata_model = {} # ConfigElementMetadata
        config_element_metadata_model['name'] = 'testString'
        config_element_metadata_model['type'] = 'testString'

        get_config_resources_item_model = {} # PublicCertSecretEngineRootConfig
        get_config_resources_item_model['certificate_authorities'] = [config_element_metadata_model]
        get_config_resources_item_model['dns_providers'] = [config_element_metadata_model]

        # Construct a json representation of a GetConfig model
        get_config_model_json = {}
        get_config_model_json['metadata'] = collection_metadata_model
        get_config_model_json['resources'] = [get_config_resources_item_model]

        # Construct a model instance of GetConfig by calling from_dict on the json representation
        get_config_model = GetConfig.from_dict(get_config_model_json)
        assert get_config_model != False

        # Construct a model instance of GetConfig by calling from_dict on the json representation
        get_config_model_dict = GetConfig.from_dict(get_config_model_json).__dict__
        get_config_model2 = GetConfig(**get_config_model_dict)

        # Verify the model instances are equivalent
        assert get_config_model == get_config_model2

        # Convert model instance back to dict and verify no loss of data
        get_config_model_json2 = get_config_model.to_dict()
        assert get_config_model_json2 == get_config_model_json

class TestModel_GetConfigElements():
    """
    Test Class for GetConfigElements
    """

    def test_get_config_elements_serialization(self):
        """
        Test serialization/deserialization for GetConfigElements
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        config_element_metadata_model = {} # ConfigElementMetadata
        config_element_metadata_model['name'] = 'testString'
        config_element_metadata_model['type'] = 'testString'

        get_config_elements_resources_item_model = {} # GetConfigElementsResourcesItemCertificateAuthoritiesConfig
        get_config_elements_resources_item_model['certificate_authorities'] = [config_element_metadata_model]

        # Construct a json representation of a GetConfigElements model
        get_config_elements_model_json = {}
        get_config_elements_model_json['metadata'] = collection_metadata_model
        get_config_elements_model_json['resources'] = [get_config_elements_resources_item_model]

        # Construct a model instance of GetConfigElements by calling from_dict on the json representation
        get_config_elements_model = GetConfigElements.from_dict(get_config_elements_model_json)
        assert get_config_elements_model != False

        # Construct a model instance of GetConfigElements by calling from_dict on the json representation
        get_config_elements_model_dict = GetConfigElements.from_dict(get_config_elements_model_json).__dict__
        get_config_elements_model2 = GetConfigElements(**get_config_elements_model_dict)

        # Verify the model instances are equivalent
        assert get_config_elements_model == get_config_elements_model2

        # Convert model instance back to dict and verify no loss of data
        get_config_elements_model_json2 = get_config_elements_model.to_dict()
        assert get_config_elements_model_json2 == get_config_elements_model_json

class TestModel_GetSecret():
    """
    Test Class for GetSecret
    """

    def test_get_secret_serialization(self):
        """
        Test serialization/deserialization for GetSecret
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_resource_model = {} # ArbitrarySecretResource
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['versions_total'] = 1
        secret_resource_model['versions'] = [{}]
        secret_resource_model['expiration_date'] = "2030-04-01T09:30:00Z"
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = { 'foo': 'bar' }

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

class TestModel_GetSecretPolicyRotationResourcesItem():
    """
    Test Class for GetSecretPolicyRotationResourcesItem
    """

    def test_get_secret_policy_rotation_resources_item_serialization(self):
        """
        Test serialization/deserialization for GetSecretPolicyRotationResourcesItem
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_policy_rotation_rotation_model = {} # SecretPolicyRotationRotationPolicyRotation
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        # Construct a json representation of a GetSecretPolicyRotationResourcesItem model
        get_secret_policy_rotation_resources_item_model_json = {}
        get_secret_policy_rotation_resources_item_model_json['id'] = 'testString'
        get_secret_policy_rotation_resources_item_model_json['crn'] = 'crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>'
        get_secret_policy_rotation_resources_item_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        get_secret_policy_rotation_resources_item_model_json['created_by'] = 'testString'
        get_secret_policy_rotation_resources_item_model_json['last_update_date'] = "2019-01-01T12:00:00Z"
        get_secret_policy_rotation_resources_item_model_json['updated_by'] = 'testString'
        get_secret_policy_rotation_resources_item_model_json['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        get_secret_policy_rotation_resources_item_model_json['rotation'] = secret_policy_rotation_rotation_model

        # Construct a model instance of GetSecretPolicyRotationResourcesItem by calling from_dict on the json representation
        get_secret_policy_rotation_resources_item_model = GetSecretPolicyRotationResourcesItem.from_dict(get_secret_policy_rotation_resources_item_model_json)
        assert get_secret_policy_rotation_resources_item_model != False

        # Construct a model instance of GetSecretPolicyRotationResourcesItem by calling from_dict on the json representation
        get_secret_policy_rotation_resources_item_model_dict = GetSecretPolicyRotationResourcesItem.from_dict(get_secret_policy_rotation_resources_item_model_json).__dict__
        get_secret_policy_rotation_resources_item_model2 = GetSecretPolicyRotationResourcesItem(**get_secret_policy_rotation_resources_item_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_policy_rotation_resources_item_model == get_secret_policy_rotation_resources_item_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_policy_rotation_resources_item_model_json2 = get_secret_policy_rotation_resources_item_model.to_dict()
        assert get_secret_policy_rotation_resources_item_model_json2 == get_secret_policy_rotation_resources_item_model_json

class TestModel_GetSecretVersion():
    """
    Test Class for GetSecretVersion
    """

    def test_get_secret_version_serialization(self):
        """
        Test serialization/deserialization for GetSecretVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        certificate_validity_model = {} # CertificateValidity
        certificate_validity_model['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model['not_after'] = "2021-01-01T00:00:00Z"

        certificate_secret_data_model = {} # CertificateSecretData
        certificate_secret_data_model['certificate'] = 'testString'
        certificate_secret_data_model['private_key'] = 'testString'
        certificate_secret_data_model['intermediate'] = 'testString'

        secret_version_model = {} # CertificateSecretVersion
        secret_version_model['id'] = 'testString'
        secret_version_model['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_version_model['version_id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_model['creation_date'] = "2019-01-01T12:00:00Z"
        secret_version_model['created_by'] = 'testString'
        secret_version_model['validity'] = certificate_validity_model
        secret_version_model['serial_number'] = 'testString'
        secret_version_model['expiration_date'] = "2030-04-01T09:30:00Z"
        secret_version_model['secret_data'] = certificate_secret_data_model

        # Construct a json representation of a GetSecretVersion model
        get_secret_version_model_json = {}
        get_secret_version_model_json['metadata'] = collection_metadata_model
        get_secret_version_model_json['resources'] = [secret_version_model]

        # Construct a model instance of GetSecretVersion by calling from_dict on the json representation
        get_secret_version_model = GetSecretVersion.from_dict(get_secret_version_model_json)
        assert get_secret_version_model != False

        # Construct a model instance of GetSecretVersion by calling from_dict on the json representation
        get_secret_version_model_dict = GetSecretVersion.from_dict(get_secret_version_model_json).__dict__
        get_secret_version_model2 = GetSecretVersion(**get_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_version_model == get_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_version_model_json2 = get_secret_version_model.to_dict()
        assert get_secret_version_model_json2 == get_secret_version_model_json

class TestModel_GetSecretVersionMetadata():
    """
    Test Class for GetSecretVersionMetadata
    """

    def test_get_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for GetSecretVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_version_metadata_model = {} # ArbitrarySecretVersionMetadata
        secret_version_metadata_model['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        secret_version_metadata_model['creation_date'] = "2019-01-01T12:00:00Z"
        secret_version_metadata_model['created_by'] = 'testString'

        # Construct a json representation of a GetSecretVersionMetadata model
        get_secret_version_metadata_model_json = {}
        get_secret_version_metadata_model_json['metadata'] = collection_metadata_model
        get_secret_version_metadata_model_json['resources'] = [secret_version_metadata_model]

        # Construct a model instance of GetSecretVersionMetadata by calling from_dict on the json representation
        get_secret_version_metadata_model = GetSecretVersionMetadata.from_dict(get_secret_version_metadata_model_json)
        assert get_secret_version_metadata_model != False

        # Construct a model instance of GetSecretVersionMetadata by calling from_dict on the json representation
        get_secret_version_metadata_model_dict = GetSecretVersionMetadata.from_dict(get_secret_version_metadata_model_json).__dict__
        get_secret_version_metadata_model2 = GetSecretVersionMetadata(**get_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_version_metadata_model == get_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_version_metadata_model_json2 = get_secret_version_metadata_model.to_dict()
        assert get_secret_version_metadata_model_json2 == get_secret_version_metadata_model_json

class TestModel_GetSingleConfigElement():
    """
    Test Class for GetSingleConfigElement
    """

    def test_get_single_config_element_serialization(self):
        """
        Test serialization/deserialization for GetSingleConfigElement
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        config_element_model = {} # ConfigElement
        config_element_model['name'] = 'testString'
        config_element_model['type'] = 'testString'
        config_element_model['config'] = { 'foo': 'bar' }

        # Construct a json representation of a GetSingleConfigElement model
        get_single_config_element_model_json = {}
        get_single_config_element_model_json['metadata'] = collection_metadata_model
        get_single_config_element_model_json['resources'] = [config_element_model]

        # Construct a model instance of GetSingleConfigElement by calling from_dict on the json representation
        get_single_config_element_model = GetSingleConfigElement.from_dict(get_single_config_element_model_json)
        assert get_single_config_element_model != False

        # Construct a model instance of GetSingleConfigElement by calling from_dict on the json representation
        get_single_config_element_model_dict = GetSingleConfigElement.from_dict(get_single_config_element_model_json).__dict__
        get_single_config_element_model2 = GetSingleConfigElement(**get_single_config_element_model_dict)

        # Verify the model instances are equivalent
        assert get_single_config_element_model == get_single_config_element_model2

        # Convert model instance back to dict and verify no loss of data
        get_single_config_element_model_json2 = get_single_config_element_model.to_dict()
        assert get_single_config_element_model_json2 == get_single_config_element_model_json

class TestModel_IssuanceInfo():
    """
    Test Class for IssuanceInfo
    """

    def test_issuance_info_serialization(self):
        """
        Test serialization/deserialization for IssuanceInfo
        """

        # Construct a json representation of a IssuanceInfo model
        issuance_info_model_json = {}
        issuance_info_model_json['ordered_on'] = "2018-04-12T23:20:50.520000Z"
        issuance_info_model_json['error_code'] = 'testString'
        issuance_info_model_json['error_message'] = 'testString'
        issuance_info_model_json['bundle_certs'] = True
        issuance_info_model_json['state'] = 0
        issuance_info_model_json['state_description'] = 'Active'
        issuance_info_model_json['auto_rotated'] = True
        issuance_info_model_json['ca'] = 'testString'
        issuance_info_model_json['dns'] = 'testString'

        # Construct a model instance of IssuanceInfo by calling from_dict on the json representation
        issuance_info_model = IssuanceInfo.from_dict(issuance_info_model_json)
        assert issuance_info_model != False

        # Construct a model instance of IssuanceInfo by calling from_dict on the json representation
        issuance_info_model_dict = IssuanceInfo.from_dict(issuance_info_model_json).__dict__
        issuance_info_model2 = IssuanceInfo(**issuance_info_model_dict)

        # Verify the model instances are equivalent
        assert issuance_info_model == issuance_info_model2

        # Convert model instance back to dict and verify no loss of data
        issuance_info_model_json2 = issuance_info_model.to_dict()
        assert issuance_info_model_json2 == issuance_info_model_json

class TestModel_ListSecrets():
    """
    Test Class for ListSecrets
    """

    def test_list_secrets_serialization(self):
        """
        Test serialization/deserialization for ListSecrets
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_resource_model = {} # ArbitrarySecretResource
        secret_resource_model['id'] = 'testString'
        secret_resource_model['name'] = 'testString'
        secret_resource_model['description'] = 'testString'
        secret_resource_model['secret_group_id'] = 'testString'
        secret_resource_model['labels'] = ['testString']
        secret_resource_model['state'] = 0
        secret_resource_model['state_description'] = 'Active'
        secret_resource_model['secret_type'] = 'arbitrary'
        secret_resource_model['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_resource_model['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['created_by'] = 'testString'
        secret_resource_model['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        secret_resource_model['versions_total'] = 1
        secret_resource_model['versions'] = [{}]
        secret_resource_model['expiration_date'] = "2030-04-01T09:30:00Z"
        secret_resource_model['payload'] = 'testString'
        secret_resource_model['secret_data'] = { 'foo': 'bar' }

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

class TestModel_Rotation():
    """
    Test Class for Rotation
    """

    def test_rotation_serialization(self):
        """
        Test serialization/deserialization for Rotation
        """

        # Construct a json representation of a Rotation model
        rotation_model_json = {}
        rotation_model_json['auto_rotate'] = True
        rotation_model_json['rotate_keys'] = True

        # Construct a model instance of Rotation by calling from_dict on the json representation
        rotation_model = Rotation.from_dict(rotation_model_json)
        assert rotation_model != False

        # Construct a model instance of Rotation by calling from_dict on the json representation
        rotation_model_dict = Rotation.from_dict(rotation_model_json).__dict__
        rotation_model2 = Rotation(**rotation_model_dict)

        # Verify the model instances are equivalent
        assert rotation_model == rotation_model2

        # Convert model instance back to dict and verify no loss of data
        rotation_model_json2 = rotation_model.to_dict()
        assert rotation_model_json2 == rotation_model_json

class TestModel_SecretGroupDef():
    """
    Test Class for SecretGroupDef
    """

    def test_secret_group_def_serialization(self):
        """
        Test serialization/deserialization for SecretGroupDef
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_group_resource_model = {} # SecretGroupResource
        secret_group_resource_model['id'] = 'bc656587-8fda-4d05-9ad8-b1de1ec7e712'
        secret_group_resource_model['name'] = 'my-secret-group'
        secret_group_resource_model['description'] = 'Extended description for this group.'
        secret_group_resource_model['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_group_resource_model['last_update_date'] = "2018-05-12T23:20:50.520000Z"
        secret_group_resource_model['type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        secret_group_resource_model['foo'] = 'testString'

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

class TestModel_SecretGroupMetadataUpdatable():
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
        secret_group_metadata_updatable_model = SecretGroupMetadataUpdatable.from_dict(secret_group_metadata_updatable_model_json)
        assert secret_group_metadata_updatable_model != False

        # Construct a model instance of SecretGroupMetadataUpdatable by calling from_dict on the json representation
        secret_group_metadata_updatable_model_dict = SecretGroupMetadataUpdatable.from_dict(secret_group_metadata_updatable_model_json).__dict__
        secret_group_metadata_updatable_model2 = SecretGroupMetadataUpdatable(**secret_group_metadata_updatable_model_dict)

        # Verify the model instances are equivalent
        assert secret_group_metadata_updatable_model == secret_group_metadata_updatable_model2

        # Convert model instance back to dict and verify no loss of data
        secret_group_metadata_updatable_model_json2 = secret_group_metadata_updatable_model.to_dict()
        assert secret_group_metadata_updatable_model_json2 == secret_group_metadata_updatable_model_json

class TestModel_SecretGroupResource():
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
        secret_group_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_group_resource_model_json['last_update_date'] = "2018-05-12T23:20:50.520000Z"
        secret_group_resource_model_json['type'] = 'application/vnd.ibm.secrets-manager.secret.group+json'
        secret_group_resource_model_json['foo'] = 'testString'

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

        # Test get_properties and set_properties methods.
        secret_group_resource_model.set_properties({})
        actual_dict = secret_group_resource_model.get_properties()
        assert actual_dict == {}

        expected_dict = {'foo': 'testString'}
        secret_group_resource_model.set_properties(expected_dict)
        actual_dict = secret_group_resource_model.get_properties()
        assert actual_dict == expected_dict

class TestModel_SecretMetadataRequest():
    """
    Test Class for SecretMetadataRequest
    """

    def test_secret_metadata_request_serialization(self):
        """
        Test serialization/deserialization for SecretMetadataRequest
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_metadata_model = {} # ArbitrarySecretMetadata
        secret_metadata_model['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        secret_metadata_model['labels'] = ['dev', 'us-south']
        secret_metadata_model['name'] = 'example-secret'
        secret_metadata_model['description'] = 'Extended description for this secret.'
        secret_metadata_model['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        secret_metadata_model['state'] = 0
        secret_metadata_model['state_description'] = 'Active'
        secret_metadata_model['secret_type'] = 'arbitrary'
        secret_metadata_model['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        secret_metadata_model['creation_date'] = "2018-04-12T23:20:50.520000Z"
        secret_metadata_model['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        secret_metadata_model['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        secret_metadata_model['versions_total'] = 1
        secret_metadata_model['expiration_date'] = "2030-04-01T09:30:00Z"

        # Construct a json representation of a SecretMetadataRequest model
        secret_metadata_request_model_json = {}
        secret_metadata_request_model_json['metadata'] = collection_metadata_model
        secret_metadata_request_model_json['resources'] = [secret_metadata_model]

        # Construct a model instance of SecretMetadataRequest by calling from_dict on the json representation
        secret_metadata_request_model = SecretMetadataRequest.from_dict(secret_metadata_request_model_json)
        assert secret_metadata_request_model != False

        # Construct a model instance of SecretMetadataRequest by calling from_dict on the json representation
        secret_metadata_request_model_dict = SecretMetadataRequest.from_dict(secret_metadata_request_model_json).__dict__
        secret_metadata_request_model2 = SecretMetadataRequest(**secret_metadata_request_model_dict)

        # Verify the model instances are equivalent
        assert secret_metadata_request_model == secret_metadata_request_model2

        # Convert model instance back to dict and verify no loss of data
        secret_metadata_request_model_json2 = secret_metadata_request_model.to_dict()
        assert secret_metadata_request_model_json2 == secret_metadata_request_model_json

class TestModel_SecretPolicyRotation():
    """
    Test Class for SecretPolicyRotation
    """

    def test_secret_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for SecretPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        secret_policy_rotation_rotation_model = {} # SecretPolicyRotationRotationPolicyRotation
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

class TestModel_CertificateValidity():
    """
    Test Class for CertificateValidity
    """

    def test_certificate_validity_serialization(self):
        """
        Test serialization/deserialization for CertificateValidity
        """

        # Construct a json representation of a CertificateValidity model
        certificate_validity_model_json = {}
        certificate_validity_model_json['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model_json['not_after'] = "2021-01-01T00:00:00Z"

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

class TestModel_ArbitrarySecretMetadata():
    """
    Test Class for ArbitrarySecretMetadata
    """

    def test_arbitrary_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretMetadata
        """

        # Construct a json representation of a ArbitrarySecretMetadata model
        arbitrary_secret_metadata_model_json = {}
        arbitrary_secret_metadata_model_json['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        arbitrary_secret_metadata_model_json['labels'] = ['dev', 'us-south']
        arbitrary_secret_metadata_model_json['name'] = 'example-secret'
        arbitrary_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        arbitrary_secret_metadata_model_json['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        arbitrary_secret_metadata_model_json['state'] = 0
        arbitrary_secret_metadata_model_json['state_description'] = 'Active'
        arbitrary_secret_metadata_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_metadata_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        arbitrary_secret_metadata_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        arbitrary_secret_metadata_model_json['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        arbitrary_secret_metadata_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        arbitrary_secret_metadata_model_json['versions_total'] = 1
        arbitrary_secret_metadata_model_json['expiration_date'] = "2030-04-01T09:30:00Z"

        # Construct a model instance of ArbitrarySecretMetadata by calling from_dict on the json representation
        arbitrary_secret_metadata_model = ArbitrarySecretMetadata.from_dict(arbitrary_secret_metadata_model_json)
        assert arbitrary_secret_metadata_model != False

        # Construct a model instance of ArbitrarySecretMetadata by calling from_dict on the json representation
        arbitrary_secret_metadata_model_dict = ArbitrarySecretMetadata.from_dict(arbitrary_secret_metadata_model_json).__dict__
        arbitrary_secret_metadata_model2 = ArbitrarySecretMetadata(**arbitrary_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_metadata_model == arbitrary_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_metadata_model_json2 = arbitrary_secret_metadata_model.to_dict()
        assert arbitrary_secret_metadata_model_json2 == arbitrary_secret_metadata_model_json

class TestModel_ArbitrarySecretResource():
    """
    Test Class for ArbitrarySecretResource
    """

    def test_arbitrary_secret_resource_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretResource
        """

        # Construct a json representation of a ArbitrarySecretResource model
        arbitrary_secret_resource_model_json = {}
        arbitrary_secret_resource_model_json['id'] = 'testString'
        arbitrary_secret_resource_model_json['name'] = 'testString'
        arbitrary_secret_resource_model_json['description'] = 'testString'
        arbitrary_secret_resource_model_json['secret_group_id'] = 'testString'
        arbitrary_secret_resource_model_json['labels'] = ['testString']
        arbitrary_secret_resource_model_json['state'] = 0
        arbitrary_secret_resource_model_json['state_description'] = 'Active'
        arbitrary_secret_resource_model_json['secret_type'] = 'arbitrary'
        arbitrary_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        arbitrary_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        arbitrary_secret_resource_model_json['created_by'] = 'testString'
        arbitrary_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        arbitrary_secret_resource_model_json['versions_total'] = 1
        arbitrary_secret_resource_model_json['versions'] = [{}]
        arbitrary_secret_resource_model_json['expiration_date'] = "2030-04-01T09:30:00Z"
        arbitrary_secret_resource_model_json['payload'] = 'testString'
        arbitrary_secret_resource_model_json['secret_data'] = { 'foo': 'bar' }

        # Construct a model instance of ArbitrarySecretResource by calling from_dict on the json representation
        arbitrary_secret_resource_model = ArbitrarySecretResource.from_dict(arbitrary_secret_resource_model_json)
        assert arbitrary_secret_resource_model != False

        # Construct a model instance of ArbitrarySecretResource by calling from_dict on the json representation
        arbitrary_secret_resource_model_dict = ArbitrarySecretResource.from_dict(arbitrary_secret_resource_model_json).__dict__
        arbitrary_secret_resource_model2 = ArbitrarySecretResource(**arbitrary_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_resource_model == arbitrary_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_resource_model_json2 = arbitrary_secret_resource_model.to_dict()
        assert arbitrary_secret_resource_model_json2 == arbitrary_secret_resource_model_json

class TestModel_ArbitrarySecretVersionMetadata():
    """
    Test Class for ArbitrarySecretVersionMetadata
    """

    def test_arbitrary_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for ArbitrarySecretVersionMetadata
        """

        # Construct a json representation of a ArbitrarySecretVersionMetadata model
        arbitrary_secret_version_metadata_model_json = {}
        arbitrary_secret_version_metadata_model_json['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        arbitrary_secret_version_metadata_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        arbitrary_secret_version_metadata_model_json['created_by'] = 'testString'

        # Construct a model instance of ArbitrarySecretVersionMetadata by calling from_dict on the json representation
        arbitrary_secret_version_metadata_model = ArbitrarySecretVersionMetadata.from_dict(arbitrary_secret_version_metadata_model_json)
        assert arbitrary_secret_version_metadata_model != False

        # Construct a model instance of ArbitrarySecretVersionMetadata by calling from_dict on the json representation
        arbitrary_secret_version_metadata_model_dict = ArbitrarySecretVersionMetadata.from_dict(arbitrary_secret_version_metadata_model_json).__dict__
        arbitrary_secret_version_metadata_model2 = ArbitrarySecretVersionMetadata(**arbitrary_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert arbitrary_secret_version_metadata_model == arbitrary_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        arbitrary_secret_version_metadata_model_json2 = arbitrary_secret_version_metadata_model.to_dict()
        assert arbitrary_secret_version_metadata_model_json2 == arbitrary_secret_version_metadata_model_json

class TestModel_CertificateSecretMetadata():
    """
    Test Class for CertificateSecretMetadata
    """

    def test_certificate_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for CertificateSecretMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {} # CertificateValidity
        certificate_validity_model['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model['not_after'] = "2021-01-01T00:00:00Z"

        # Construct a json representation of a CertificateSecretMetadata model
        certificate_secret_metadata_model_json = {}
        certificate_secret_metadata_model_json['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        certificate_secret_metadata_model_json['labels'] = ['dev', 'us-south']
        certificate_secret_metadata_model_json['name'] = 'example-secret'
        certificate_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        certificate_secret_metadata_model_json['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        certificate_secret_metadata_model_json['state'] = 0
        certificate_secret_metadata_model_json['state_description'] = 'Active'
        certificate_secret_metadata_model_json['secret_type'] = 'arbitrary'
        certificate_secret_metadata_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        certificate_secret_metadata_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        certificate_secret_metadata_model_json['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        certificate_secret_metadata_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        certificate_secret_metadata_model_json['versions_total'] = 1
        certificate_secret_metadata_model_json['serial_number'] = 'd9:be:fe:35:ba:09:42:b5'
        certificate_secret_metadata_model_json['algorithm'] = 'SHA256-RSA'
        certificate_secret_metadata_model_json['key_algorithm'] = 'RSA2048'
        certificate_secret_metadata_model_json['issuer'] = 'GlobalSign'
        certificate_secret_metadata_model_json['validity'] = certificate_validity_model
        certificate_secret_metadata_model_json['common_name'] = 'example.com'
        certificate_secret_metadata_model_json['intermediate_included'] = True
        certificate_secret_metadata_model_json['private_key_included'] = True
        certificate_secret_metadata_model_json['alt_names'] = ['testString']
        certificate_secret_metadata_model_json['expiration_date'] = "2030-04-01T09:30:00Z"

        # Construct a model instance of CertificateSecretMetadata by calling from_dict on the json representation
        certificate_secret_metadata_model = CertificateSecretMetadata.from_dict(certificate_secret_metadata_model_json)
        assert certificate_secret_metadata_model != False

        # Construct a model instance of CertificateSecretMetadata by calling from_dict on the json representation
        certificate_secret_metadata_model_dict = CertificateSecretMetadata.from_dict(certificate_secret_metadata_model_json).__dict__
        certificate_secret_metadata_model2 = CertificateSecretMetadata(**certificate_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert certificate_secret_metadata_model == certificate_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_secret_metadata_model_json2 = certificate_secret_metadata_model.to_dict()
        assert certificate_secret_metadata_model_json2 == certificate_secret_metadata_model_json

class TestModel_CertificateSecretResource():
    """
    Test Class for CertificateSecretResource
    """

    def test_certificate_secret_resource_serialization(self):
        """
        Test serialization/deserialization for CertificateSecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {} # CertificateValidity
        certificate_validity_model['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model['not_after'] = "2021-01-01T00:00:00Z"

        # Construct a json representation of a CertificateSecretResource model
        certificate_secret_resource_model_json = {}
        certificate_secret_resource_model_json['id'] = 'testString'
        certificate_secret_resource_model_json['name'] = 'testString'
        certificate_secret_resource_model_json['description'] = 'testString'
        certificate_secret_resource_model_json['secret_group_id'] = 'testString'
        certificate_secret_resource_model_json['labels'] = ['testString']
        certificate_secret_resource_model_json['state'] = 0
        certificate_secret_resource_model_json['state_description'] = 'Active'
        certificate_secret_resource_model_json['secret_type'] = 'arbitrary'
        certificate_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        certificate_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        certificate_secret_resource_model_json['created_by'] = 'testString'
        certificate_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        certificate_secret_resource_model_json['versions_total'] = 1
        certificate_secret_resource_model_json['versions'] = [{}]
        certificate_secret_resource_model_json['certificate'] = 'testString'
        certificate_secret_resource_model_json['private_key'] = 'testString'
        certificate_secret_resource_model_json['intermediate'] = 'testString'
        certificate_secret_resource_model_json['secret_data'] = { 'foo': 'bar' }
        certificate_secret_resource_model_json['serial_number'] = 'd9:be:fe:35:ba:09:42:b5'
        certificate_secret_resource_model_json['algorithm'] = 'sha256WithRSAEncryption'
        certificate_secret_resource_model_json['key_algorithm'] = 'RSA2048'
        certificate_secret_resource_model_json['issuer'] = 'GlobalSign'
        certificate_secret_resource_model_json['validity'] = certificate_validity_model
        certificate_secret_resource_model_json['common_name'] = 'example.com'
        certificate_secret_resource_model_json['intermediate_included'] = True
        certificate_secret_resource_model_json['private_key_included'] = True
        certificate_secret_resource_model_json['alt_names'] = ['testString']
        certificate_secret_resource_model_json['expiration_date'] = "2030-04-01T09:30:00Z"

        # Construct a model instance of CertificateSecretResource by calling from_dict on the json representation
        certificate_secret_resource_model = CertificateSecretResource.from_dict(certificate_secret_resource_model_json)
        assert certificate_secret_resource_model != False

        # Construct a model instance of CertificateSecretResource by calling from_dict on the json representation
        certificate_secret_resource_model_dict = CertificateSecretResource.from_dict(certificate_secret_resource_model_json).__dict__
        certificate_secret_resource_model2 = CertificateSecretResource(**certificate_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert certificate_secret_resource_model == certificate_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_secret_resource_model_json2 = certificate_secret_resource_model.to_dict()
        assert certificate_secret_resource_model_json2 == certificate_secret_resource_model_json

class TestModel_CertificateSecretVersion():
    """
    Test Class for CertificateSecretVersion
    """

    def test_certificate_secret_version_serialization(self):
        """
        Test serialization/deserialization for CertificateSecretVersion
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {} # CertificateValidity
        certificate_validity_model['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model['not_after'] = "2021-01-01T00:00:00Z"

        certificate_secret_data_model = {} # CertificateSecretData
        certificate_secret_data_model['certificate'] = 'testString'
        certificate_secret_data_model['private_key'] = 'testString'
        certificate_secret_data_model['intermediate'] = 'testString'

        # Construct a json representation of a CertificateSecretVersion model
        certificate_secret_version_model_json = {}
        certificate_secret_version_model_json['id'] = 'testString'
        certificate_secret_version_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        certificate_secret_version_model_json['version_id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        certificate_secret_version_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        certificate_secret_version_model_json['created_by'] = 'testString'
        certificate_secret_version_model_json['validity'] = certificate_validity_model
        certificate_secret_version_model_json['serial_number'] = 'testString'
        certificate_secret_version_model_json['expiration_date'] = "2030-04-01T09:30:00Z"
        certificate_secret_version_model_json['secret_data'] = certificate_secret_data_model

        # Construct a model instance of CertificateSecretVersion by calling from_dict on the json representation
        certificate_secret_version_model = CertificateSecretVersion.from_dict(certificate_secret_version_model_json)
        assert certificate_secret_version_model != False

        # Construct a model instance of CertificateSecretVersion by calling from_dict on the json representation
        certificate_secret_version_model_dict = CertificateSecretVersion.from_dict(certificate_secret_version_model_json).__dict__
        certificate_secret_version_model2 = CertificateSecretVersion(**certificate_secret_version_model_dict)

        # Verify the model instances are equivalent
        assert certificate_secret_version_model == certificate_secret_version_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_secret_version_model_json2 = certificate_secret_version_model.to_dict()
        assert certificate_secret_version_model_json2 == certificate_secret_version_model_json

class TestModel_CertificateSecretVersionMetadata():
    """
    Test Class for CertificateSecretVersionMetadata
    """

    def test_certificate_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for CertificateSecretVersionMetadata
        """

        # Construct dict forms of any model objects needed in order to build this model.

        certificate_validity_model = {} # CertificateValidity
        certificate_validity_model['not_before'] = "2020-10-05T21:33:11Z"
        certificate_validity_model['not_after'] = "2021-01-01T00:00:00Z"

        # Construct a json representation of a CertificateSecretVersionMetadata model
        certificate_secret_version_metadata_model_json = {}
        certificate_secret_version_metadata_model_json['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        certificate_secret_version_metadata_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        certificate_secret_version_metadata_model_json['created_by'] = 'testString'
        certificate_secret_version_metadata_model_json['serial_number'] = 'testString'
        certificate_secret_version_metadata_model_json['expiration_date'] = "2030-04-01T09:30:00Z"
        certificate_secret_version_metadata_model_json['validity'] = certificate_validity_model

        # Construct a model instance of CertificateSecretVersionMetadata by calling from_dict on the json representation
        certificate_secret_version_metadata_model = CertificateSecretVersionMetadata.from_dict(certificate_secret_version_metadata_model_json)
        assert certificate_secret_version_metadata_model != False

        # Construct a model instance of CertificateSecretVersionMetadata by calling from_dict on the json representation
        certificate_secret_version_metadata_model_dict = CertificateSecretVersionMetadata.from_dict(certificate_secret_version_metadata_model_json).__dict__
        certificate_secret_version_metadata_model2 = CertificateSecretVersionMetadata(**certificate_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert certificate_secret_version_metadata_model == certificate_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        certificate_secret_version_metadata_model_json2 = certificate_secret_version_metadata_model.to_dict()
        assert certificate_secret_version_metadata_model_json2 == certificate_secret_version_metadata_model_json

class TestModel_DeleteCredentialsForIAMCredentialsSecret():
    """
    Test Class for DeleteCredentialsForIAMCredentialsSecret
    """

    def test_delete_credentials_for_iam_credentials_secret_serialization(self):
        """
        Test serialization/deserialization for DeleteCredentialsForIAMCredentialsSecret
        """

        # Construct a json representation of a DeleteCredentialsForIAMCredentialsSecret model
        delete_credentials_for_iam_credentials_secret_model_json = {}
        delete_credentials_for_iam_credentials_secret_model_json['service_id'] = 'testString'

        # Construct a model instance of DeleteCredentialsForIAMCredentialsSecret by calling from_dict on the json representation
        delete_credentials_for_iam_credentials_secret_model = DeleteCredentialsForIAMCredentialsSecret.from_dict(delete_credentials_for_iam_credentials_secret_model_json)
        assert delete_credentials_for_iam_credentials_secret_model != False

        # Construct a model instance of DeleteCredentialsForIAMCredentialsSecret by calling from_dict on the json representation
        delete_credentials_for_iam_credentials_secret_model_dict = DeleteCredentialsForIAMCredentialsSecret.from_dict(delete_credentials_for_iam_credentials_secret_model_json).__dict__
        delete_credentials_for_iam_credentials_secret_model2 = DeleteCredentialsForIAMCredentialsSecret(**delete_credentials_for_iam_credentials_secret_model_dict)

        # Verify the model instances are equivalent
        assert delete_credentials_for_iam_credentials_secret_model == delete_credentials_for_iam_credentials_secret_model2

        # Convert model instance back to dict and verify no loss of data
        delete_credentials_for_iam_credentials_secret_model_json2 = delete_credentials_for_iam_credentials_secret_model.to_dict()
        assert delete_credentials_for_iam_credentials_secret_model_json2 == delete_credentials_for_iam_credentials_secret_model_json

class TestModel_GetConfigElementsResourcesItemCertificateAuthoritiesConfig():
    """
    Test Class for GetConfigElementsResourcesItemCertificateAuthoritiesConfig
    """

    def test_get_config_elements_resources_item_certificate_authorities_config_serialization(self):
        """
        Test serialization/deserialization for GetConfigElementsResourcesItemCertificateAuthoritiesConfig
        """

        # Construct dict forms of any model objects needed in order to build this model.

        config_element_metadata_model = {} # ConfigElementMetadata
        config_element_metadata_model['name'] = 'testString'
        config_element_metadata_model['type'] = 'testString'

        # Construct a json representation of a GetConfigElementsResourcesItemCertificateAuthoritiesConfig model
        get_config_elements_resources_item_certificate_authorities_config_model_json = {}
        get_config_elements_resources_item_certificate_authorities_config_model_json['certificate_authorities'] = [config_element_metadata_model]

        # Construct a model instance of GetConfigElementsResourcesItemCertificateAuthoritiesConfig by calling from_dict on the json representation
        get_config_elements_resources_item_certificate_authorities_config_model = GetConfigElementsResourcesItemCertificateAuthoritiesConfig.from_dict(get_config_elements_resources_item_certificate_authorities_config_model_json)
        assert get_config_elements_resources_item_certificate_authorities_config_model != False

        # Construct a model instance of GetConfigElementsResourcesItemCertificateAuthoritiesConfig by calling from_dict on the json representation
        get_config_elements_resources_item_certificate_authorities_config_model_dict = GetConfigElementsResourcesItemCertificateAuthoritiesConfig.from_dict(get_config_elements_resources_item_certificate_authorities_config_model_json).__dict__
        get_config_elements_resources_item_certificate_authorities_config_model2 = GetConfigElementsResourcesItemCertificateAuthoritiesConfig(**get_config_elements_resources_item_certificate_authorities_config_model_dict)

        # Verify the model instances are equivalent
        assert get_config_elements_resources_item_certificate_authorities_config_model == get_config_elements_resources_item_certificate_authorities_config_model2

        # Convert model instance back to dict and verify no loss of data
        get_config_elements_resources_item_certificate_authorities_config_model_json2 = get_config_elements_resources_item_certificate_authorities_config_model.to_dict()
        assert get_config_elements_resources_item_certificate_authorities_config_model_json2 == get_config_elements_resources_item_certificate_authorities_config_model_json

class TestModel_GetConfigElementsResourcesItemDnsProvidersConfig():
    """
    Test Class for GetConfigElementsResourcesItemDnsProvidersConfig
    """

    def test_get_config_elements_resources_item_dns_providers_config_serialization(self):
        """
        Test serialization/deserialization for GetConfigElementsResourcesItemDnsProvidersConfig
        """

        # Construct dict forms of any model objects needed in order to build this model.

        config_element_metadata_model = {} # ConfigElementMetadata
        config_element_metadata_model['name'] = 'testString'
        config_element_metadata_model['type'] = 'testString'

        # Construct a json representation of a GetConfigElementsResourcesItemDnsProvidersConfig model
        get_config_elements_resources_item_dns_providers_config_model_json = {}
        get_config_elements_resources_item_dns_providers_config_model_json['dns_providers'] = [config_element_metadata_model]

        # Construct a model instance of GetConfigElementsResourcesItemDnsProvidersConfig by calling from_dict on the json representation
        get_config_elements_resources_item_dns_providers_config_model = GetConfigElementsResourcesItemDnsProvidersConfig.from_dict(get_config_elements_resources_item_dns_providers_config_model_json)
        assert get_config_elements_resources_item_dns_providers_config_model != False

        # Construct a model instance of GetConfigElementsResourcesItemDnsProvidersConfig by calling from_dict on the json representation
        get_config_elements_resources_item_dns_providers_config_model_dict = GetConfigElementsResourcesItemDnsProvidersConfig.from_dict(get_config_elements_resources_item_dns_providers_config_model_json).__dict__
        get_config_elements_resources_item_dns_providers_config_model2 = GetConfigElementsResourcesItemDnsProvidersConfig(**get_config_elements_resources_item_dns_providers_config_model_dict)

        # Verify the model instances are equivalent
        assert get_config_elements_resources_item_dns_providers_config_model == get_config_elements_resources_item_dns_providers_config_model2

        # Convert model instance back to dict and verify no loss of data
        get_config_elements_resources_item_dns_providers_config_model_json2 = get_config_elements_resources_item_dns_providers_config_model.to_dict()
        assert get_config_elements_resources_item_dns_providers_config_model_json2 == get_config_elements_resources_item_dns_providers_config_model_json

class TestModel_GetSecretPolicyRotation():
    """
    Test Class for GetSecretPolicyRotation
    """

    def test_get_secret_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for GetSecretPolicyRotation
        """

        # Construct dict forms of any model objects needed in order to build this model.

        collection_metadata_model = {} # CollectionMetadata
        collection_metadata_model['collection_type'] = 'application/vnd.ibm.secrets-manager.config+json'
        collection_metadata_model['collection_total'] = 1

        secret_policy_rotation_rotation_model = {} # SecretPolicyRotationRotationPolicyRotation
        secret_policy_rotation_rotation_model['interval'] = 1
        secret_policy_rotation_rotation_model['unit'] = 'day'

        get_secret_policy_rotation_resources_item_model = {} # GetSecretPolicyRotationResourcesItem
        get_secret_policy_rotation_resources_item_model['id'] = 'testString'
        get_secret_policy_rotation_resources_item_model['crn'] = 'crn:v1:bluemix:public:kms:<region>:a/<account-id>:<service-instance:policy:<policy-id>'
        get_secret_policy_rotation_resources_item_model['creation_date'] = "2019-01-01T12:00:00Z"
        get_secret_policy_rotation_resources_item_model['created_by'] = 'testString'
        get_secret_policy_rotation_resources_item_model['last_update_date'] = "2019-01-01T12:00:00Z"
        get_secret_policy_rotation_resources_item_model['updated_by'] = 'testString'
        get_secret_policy_rotation_resources_item_model['type'] = 'application/vnd.ibm.secrets-manager.secret.policy+json'
        get_secret_policy_rotation_resources_item_model['rotation'] = secret_policy_rotation_rotation_model

        # Construct a json representation of a GetSecretPolicyRotation model
        get_secret_policy_rotation_model_json = {}
        get_secret_policy_rotation_model_json['metadata'] = collection_metadata_model
        get_secret_policy_rotation_model_json['resources'] = [get_secret_policy_rotation_resources_item_model]

        # Construct a model instance of GetSecretPolicyRotation by calling from_dict on the json representation
        get_secret_policy_rotation_model = GetSecretPolicyRotation.from_dict(get_secret_policy_rotation_model_json)
        assert get_secret_policy_rotation_model != False

        # Construct a model instance of GetSecretPolicyRotation by calling from_dict on the json representation
        get_secret_policy_rotation_model_dict = GetSecretPolicyRotation.from_dict(get_secret_policy_rotation_model_json).__dict__
        get_secret_policy_rotation_model2 = GetSecretPolicyRotation(**get_secret_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert get_secret_policy_rotation_model == get_secret_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        get_secret_policy_rotation_model_json2 = get_secret_policy_rotation_model.to_dict()
        assert get_secret_policy_rotation_model_json2 == get_secret_policy_rotation_model_json

class TestModel_IAMCredentialsSecretEngineRootConfig():
    """
    Test Class for IAMCredentialsSecretEngineRootConfig
    """

    def test_iam_credentials_secret_engine_root_config_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretEngineRootConfig
        """

        # Construct a json representation of a IAMCredentialsSecretEngineRootConfig model
        iam_credentials_secret_engine_root_config_model_json = {}
        iam_credentials_secret_engine_root_config_model_json['api_key'] = 'API_KEY'
        iam_credentials_secret_engine_root_config_model_json['api_key_hash'] = 'a737c3a98ebfc16a0d5ddc6b277548491440780003e06f5924dc906bc8d78e91'

        # Construct a model instance of IAMCredentialsSecretEngineRootConfig by calling from_dict on the json representation
        iam_credentials_secret_engine_root_config_model = IAMCredentialsSecretEngineRootConfig.from_dict(iam_credentials_secret_engine_root_config_model_json)
        assert iam_credentials_secret_engine_root_config_model != False

        # Construct a model instance of IAMCredentialsSecretEngineRootConfig by calling from_dict on the json representation
        iam_credentials_secret_engine_root_config_model_dict = IAMCredentialsSecretEngineRootConfig.from_dict(iam_credentials_secret_engine_root_config_model_json).__dict__
        iam_credentials_secret_engine_root_config_model2 = IAMCredentialsSecretEngineRootConfig(**iam_credentials_secret_engine_root_config_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_engine_root_config_model == iam_credentials_secret_engine_root_config_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_engine_root_config_model_json2 = iam_credentials_secret_engine_root_config_model.to_dict()
        assert iam_credentials_secret_engine_root_config_model_json2 == iam_credentials_secret_engine_root_config_model_json

class TestModel_IAMCredentialsSecretMetadata():
    """
    Test Class for IAMCredentialsSecretMetadata
    """

    def test_iam_credentials_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretMetadata
        """

        # Construct a json representation of a IAMCredentialsSecretMetadata model
        iam_credentials_secret_metadata_model_json = {}
        iam_credentials_secret_metadata_model_json['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        iam_credentials_secret_metadata_model_json['labels'] = ['dev', 'us-south']
        iam_credentials_secret_metadata_model_json['name'] = 'example-secret'
        iam_credentials_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        iam_credentials_secret_metadata_model_json['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        iam_credentials_secret_metadata_model_json['state'] = 0
        iam_credentials_secret_metadata_model_json['state_description'] = 'Active'
        iam_credentials_secret_metadata_model_json['secret_type'] = 'arbitrary'
        iam_credentials_secret_metadata_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        iam_credentials_secret_metadata_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        iam_credentials_secret_metadata_model_json['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        iam_credentials_secret_metadata_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        iam_credentials_secret_metadata_model_json['versions_total'] = 1
        iam_credentials_secret_metadata_model_json['ttl'] = '24h'
        iam_credentials_secret_metadata_model_json['reuse_api_key'] = True

        # Construct a model instance of IAMCredentialsSecretMetadata by calling from_dict on the json representation
        iam_credentials_secret_metadata_model = IAMCredentialsSecretMetadata.from_dict(iam_credentials_secret_metadata_model_json)
        assert iam_credentials_secret_metadata_model != False

        # Construct a model instance of IAMCredentialsSecretMetadata by calling from_dict on the json representation
        iam_credentials_secret_metadata_model_dict = IAMCredentialsSecretMetadata.from_dict(iam_credentials_secret_metadata_model_json).__dict__
        iam_credentials_secret_metadata_model2 = IAMCredentialsSecretMetadata(**iam_credentials_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_metadata_model == iam_credentials_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_metadata_model_json2 = iam_credentials_secret_metadata_model.to_dict()
        assert iam_credentials_secret_metadata_model_json2 == iam_credentials_secret_metadata_model_json

class TestModel_IAMCredentialsSecretResource():
    """
    Test Class for IAMCredentialsSecretResource
    """

    def test_iam_credentials_secret_resource_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretResource
        """

        # Construct a json representation of a IAMCredentialsSecretResource model
        iam_credentials_secret_resource_model_json = {}
        iam_credentials_secret_resource_model_json['id'] = 'testString'
        iam_credentials_secret_resource_model_json['name'] = 'testString'
        iam_credentials_secret_resource_model_json['description'] = 'testString'
        iam_credentials_secret_resource_model_json['secret_group_id'] = 'testString'
        iam_credentials_secret_resource_model_json['labels'] = ['testString']
        iam_credentials_secret_resource_model_json['state'] = 0
        iam_credentials_secret_resource_model_json['state_description'] = 'Active'
        iam_credentials_secret_resource_model_json['secret_type'] = 'arbitrary'
        iam_credentials_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        iam_credentials_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        iam_credentials_secret_resource_model_json['created_by'] = 'testString'
        iam_credentials_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        iam_credentials_secret_resource_model_json['versions_total'] = 1
        iam_credentials_secret_resource_model_json['versions'] = [{}]
        iam_credentials_secret_resource_model_json['ttl'] = '24h'
        iam_credentials_secret_resource_model_json['access_groups'] = ['AccessGroupId-45884031-54be-4dd7-86ff-112511e92699', 'AccessGroupId-2c190fb5-0d9d-46c5-acf3-78ecd30e24a0']
        iam_credentials_secret_resource_model_json['api_key'] = 'testString'
        iam_credentials_secret_resource_model_json['service_id'] = 'testString'
        iam_credentials_secret_resource_model_json['reuse_api_key'] = False

        # Construct a model instance of IAMCredentialsSecretResource by calling from_dict on the json representation
        iam_credentials_secret_resource_model = IAMCredentialsSecretResource.from_dict(iam_credentials_secret_resource_model_json)
        assert iam_credentials_secret_resource_model != False

        # Construct a model instance of IAMCredentialsSecretResource by calling from_dict on the json representation
        iam_credentials_secret_resource_model_dict = IAMCredentialsSecretResource.from_dict(iam_credentials_secret_resource_model_json).__dict__
        iam_credentials_secret_resource_model2 = IAMCredentialsSecretResource(**iam_credentials_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_resource_model == iam_credentials_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_resource_model_json2 = iam_credentials_secret_resource_model.to_dict()
        assert iam_credentials_secret_resource_model_json2 == iam_credentials_secret_resource_model_json

class TestModel_IAMCredentialsSecretVersionMetadata():
    """
    Test Class for IAMCredentialsSecretVersionMetadata
    """

    def test_iam_credentials_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for IAMCredentialsSecretVersionMetadata
        """

        # Construct a json representation of a IAMCredentialsSecretVersionMetadata model
        iam_credentials_secret_version_metadata_model_json = {}
        iam_credentials_secret_version_metadata_model_json['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        iam_credentials_secret_version_metadata_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        iam_credentials_secret_version_metadata_model_json['created_by'] = 'testString'

        # Construct a model instance of IAMCredentialsSecretVersionMetadata by calling from_dict on the json representation
        iam_credentials_secret_version_metadata_model = IAMCredentialsSecretVersionMetadata.from_dict(iam_credentials_secret_version_metadata_model_json)
        assert iam_credentials_secret_version_metadata_model != False

        # Construct a model instance of IAMCredentialsSecretVersionMetadata by calling from_dict on the json representation
        iam_credentials_secret_version_metadata_model_dict = IAMCredentialsSecretVersionMetadata.from_dict(iam_credentials_secret_version_metadata_model_json).__dict__
        iam_credentials_secret_version_metadata_model2 = IAMCredentialsSecretVersionMetadata(**iam_credentials_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert iam_credentials_secret_version_metadata_model == iam_credentials_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        iam_credentials_secret_version_metadata_model_json2 = iam_credentials_secret_version_metadata_model.to_dict()
        assert iam_credentials_secret_version_metadata_model_json2 == iam_credentials_secret_version_metadata_model_json

class TestModel_PublicCertSecretEngineRootConfig():
    """
    Test Class for PublicCertSecretEngineRootConfig
    """

    def test_public_cert_secret_engine_root_config_serialization(self):
        """
        Test serialization/deserialization for PublicCertSecretEngineRootConfig
        """

        # Construct dict forms of any model objects needed in order to build this model.

        config_element_metadata_model = {} # ConfigElementMetadata
        config_element_metadata_model['name'] = 'testString'
        config_element_metadata_model['type'] = 'testString'

        # Construct a json representation of a PublicCertSecretEngineRootConfig model
        public_cert_secret_engine_root_config_model_json = {}
        public_cert_secret_engine_root_config_model_json['certificate_authorities'] = [config_element_metadata_model]
        public_cert_secret_engine_root_config_model_json['dns_providers'] = [config_element_metadata_model]

        # Construct a model instance of PublicCertSecretEngineRootConfig by calling from_dict on the json representation
        public_cert_secret_engine_root_config_model = PublicCertSecretEngineRootConfig.from_dict(public_cert_secret_engine_root_config_model_json)
        assert public_cert_secret_engine_root_config_model != False

        # Construct a model instance of PublicCertSecretEngineRootConfig by calling from_dict on the json representation
        public_cert_secret_engine_root_config_model_dict = PublicCertSecretEngineRootConfig.from_dict(public_cert_secret_engine_root_config_model_json).__dict__
        public_cert_secret_engine_root_config_model2 = PublicCertSecretEngineRootConfig(**public_cert_secret_engine_root_config_model_dict)

        # Verify the model instances are equivalent
        assert public_cert_secret_engine_root_config_model == public_cert_secret_engine_root_config_model2

        # Convert model instance back to dict and verify no loss of data
        public_cert_secret_engine_root_config_model_json2 = public_cert_secret_engine_root_config_model.to_dict()
        assert public_cert_secret_engine_root_config_model_json2 == public_cert_secret_engine_root_config_model_json

class TestModel_PublicCertificateMetadataSecretResource():
    """
    Test Class for PublicCertificateMetadataSecretResource
    """

    def test_public_certificate_metadata_secret_resource_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateMetadataSecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_model = {} # Rotation
        rotation_model['auto_rotate'] = True
        rotation_model['rotate_keys'] = True

        issuance_info_model = {} # IssuanceInfo
        issuance_info_model['ordered_on'] = "2018-04-12T23:20:50.520000Z"
        issuance_info_model['error_code'] = 'testString'
        issuance_info_model['error_message'] = 'testString'
        issuance_info_model['bundle_certs'] = True
        issuance_info_model['state'] = 0
        issuance_info_model['state_description'] = 'Active'
        issuance_info_model['auto_rotated'] = True
        issuance_info_model['ca'] = 'testString'
        issuance_info_model['dns'] = 'testString'

        # Construct a json representation of a PublicCertificateMetadataSecretResource model
        public_certificate_metadata_secret_resource_model_json = {}
        public_certificate_metadata_secret_resource_model_json['id'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['name'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['description'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['secret_group_id'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['labels'] = ['testString']
        public_certificate_metadata_secret_resource_model_json['state'] = 0
        public_certificate_metadata_secret_resource_model_json['state_description'] = 'Active'
        public_certificate_metadata_secret_resource_model_json['secret_type'] = 'arbitrary'
        public_certificate_metadata_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        public_certificate_metadata_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        public_certificate_metadata_secret_resource_model_json['created_by'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        public_certificate_metadata_secret_resource_model_json['versions_total'] = 1
        public_certificate_metadata_secret_resource_model_json['versions'] = [{}]
        public_certificate_metadata_secret_resource_model_json['issuer'] = 'GlobalSign'
        public_certificate_metadata_secret_resource_model_json['bundle_certs'] = True
        public_certificate_metadata_secret_resource_model_json['ca'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['dns'] = 'testString'
        public_certificate_metadata_secret_resource_model_json['algorithm'] = 'SHA256-RSA'
        public_certificate_metadata_secret_resource_model_json['key_algorithm'] = 'RSA2048'
        public_certificate_metadata_secret_resource_model_json['alt_names'] = ['testString']
        public_certificate_metadata_secret_resource_model_json['common_name'] = 'example.com'
        public_certificate_metadata_secret_resource_model_json['rotation'] = rotation_model
        public_certificate_metadata_secret_resource_model_json['issuance_info'] = issuance_info_model

        # Construct a model instance of PublicCertificateMetadataSecretResource by calling from_dict on the json representation
        public_certificate_metadata_secret_resource_model = PublicCertificateMetadataSecretResource.from_dict(public_certificate_metadata_secret_resource_model_json)
        assert public_certificate_metadata_secret_resource_model != False

        # Construct a model instance of PublicCertificateMetadataSecretResource by calling from_dict on the json representation
        public_certificate_metadata_secret_resource_model_dict = PublicCertificateMetadataSecretResource.from_dict(public_certificate_metadata_secret_resource_model_json).__dict__
        public_certificate_metadata_secret_resource_model2 = PublicCertificateMetadataSecretResource(**public_certificate_metadata_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_metadata_secret_resource_model == public_certificate_metadata_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_metadata_secret_resource_model_json2 = public_certificate_metadata_secret_resource_model.to_dict()
        assert public_certificate_metadata_secret_resource_model_json2 == public_certificate_metadata_secret_resource_model_json

class TestModel_PublicCertificateSecretResource():
    """
    Test Class for PublicCertificateSecretResource
    """

    def test_public_certificate_secret_resource_serialization(self):
        """
        Test serialization/deserialization for PublicCertificateSecretResource
        """

        # Construct dict forms of any model objects needed in order to build this model.

        rotation_model = {} # Rotation
        rotation_model['auto_rotate'] = True
        rotation_model['rotate_keys'] = True

        issuance_info_model = {} # IssuanceInfo
        issuance_info_model['ordered_on'] = "2018-04-12T23:20:50.520000Z"
        issuance_info_model['error_code'] = 'testString'
        issuance_info_model['error_message'] = 'testString'
        issuance_info_model['bundle_certs'] = True
        issuance_info_model['state'] = 0
        issuance_info_model['state_description'] = 'Active'
        issuance_info_model['auto_rotated'] = True
        issuance_info_model['ca'] = 'testString'
        issuance_info_model['dns'] = 'testString'

        # Construct a json representation of a PublicCertificateSecretResource model
        public_certificate_secret_resource_model_json = {}
        public_certificate_secret_resource_model_json['id'] = 'testString'
        public_certificate_secret_resource_model_json['name'] = 'testString'
        public_certificate_secret_resource_model_json['description'] = 'testString'
        public_certificate_secret_resource_model_json['secret_group_id'] = 'testString'
        public_certificate_secret_resource_model_json['labels'] = ['testString']
        public_certificate_secret_resource_model_json['state'] = 0
        public_certificate_secret_resource_model_json['state_description'] = 'Active'
        public_certificate_secret_resource_model_json['secret_type'] = 'arbitrary'
        public_certificate_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        public_certificate_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        public_certificate_secret_resource_model_json['created_by'] = 'testString'
        public_certificate_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        public_certificate_secret_resource_model_json['versions_total'] = 1
        public_certificate_secret_resource_model_json['versions'] = [{}]
        public_certificate_secret_resource_model_json['issuer'] = 'GlobalSign'
        public_certificate_secret_resource_model_json['bundle_certs'] = True
        public_certificate_secret_resource_model_json['ca'] = 'testString'
        public_certificate_secret_resource_model_json['dns'] = 'testString'
        public_certificate_secret_resource_model_json['algorithm'] = 'SHA256-RSA'
        public_certificate_secret_resource_model_json['key_algorithm'] = 'RSA2048'
        public_certificate_secret_resource_model_json['alt_names'] = ['testString']
        public_certificate_secret_resource_model_json['common_name'] = 'example.com'
        public_certificate_secret_resource_model_json['rotation'] = rotation_model
        public_certificate_secret_resource_model_json['issuance_info'] = issuance_info_model
        public_certificate_secret_resource_model_json['secret_data'] = { 'foo': 'bar' }

        # Construct a model instance of PublicCertificateSecretResource by calling from_dict on the json representation
        public_certificate_secret_resource_model = PublicCertificateSecretResource.from_dict(public_certificate_secret_resource_model_json)
        assert public_certificate_secret_resource_model != False

        # Construct a model instance of PublicCertificateSecretResource by calling from_dict on the json representation
        public_certificate_secret_resource_model_dict = PublicCertificateSecretResource.from_dict(public_certificate_secret_resource_model_json).__dict__
        public_certificate_secret_resource_model2 = PublicCertificateSecretResource(**public_certificate_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert public_certificate_secret_resource_model == public_certificate_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        public_certificate_secret_resource_model_json2 = public_certificate_secret_resource_model.to_dict()
        assert public_certificate_secret_resource_model_json2 == public_certificate_secret_resource_model_json

class TestModel_RotateArbitrarySecretBody():
    """
    Test Class for RotateArbitrarySecretBody
    """

    def test_rotate_arbitrary_secret_body_serialization(self):
        """
        Test serialization/deserialization for RotateArbitrarySecretBody
        """

        # Construct a json representation of a RotateArbitrarySecretBody model
        rotate_arbitrary_secret_body_model_json = {}
        rotate_arbitrary_secret_body_model_json['payload'] = 'testString'

        # Construct a model instance of RotateArbitrarySecretBody by calling from_dict on the json representation
        rotate_arbitrary_secret_body_model = RotateArbitrarySecretBody.from_dict(rotate_arbitrary_secret_body_model_json)
        assert rotate_arbitrary_secret_body_model != False

        # Construct a model instance of RotateArbitrarySecretBody by calling from_dict on the json representation
        rotate_arbitrary_secret_body_model_dict = RotateArbitrarySecretBody.from_dict(rotate_arbitrary_secret_body_model_json).__dict__
        rotate_arbitrary_secret_body_model2 = RotateArbitrarySecretBody(**rotate_arbitrary_secret_body_model_dict)

        # Verify the model instances are equivalent
        assert rotate_arbitrary_secret_body_model == rotate_arbitrary_secret_body_model2

        # Convert model instance back to dict and verify no loss of data
        rotate_arbitrary_secret_body_model_json2 = rotate_arbitrary_secret_body_model.to_dict()
        assert rotate_arbitrary_secret_body_model_json2 == rotate_arbitrary_secret_body_model_json

class TestModel_RotateCertificateBody():
    """
    Test Class for RotateCertificateBody
    """

    def test_rotate_certificate_body_serialization(self):
        """
        Test serialization/deserialization for RotateCertificateBody
        """

        # Construct a json representation of a RotateCertificateBody model
        rotate_certificate_body_model_json = {}
        rotate_certificate_body_model_json['certificate'] = 'testString'
        rotate_certificate_body_model_json['private_key'] = 'testString'
        rotate_certificate_body_model_json['intermediate'] = 'testString'

        # Construct a model instance of RotateCertificateBody by calling from_dict on the json representation
        rotate_certificate_body_model = RotateCertificateBody.from_dict(rotate_certificate_body_model_json)
        assert rotate_certificate_body_model != False

        # Construct a model instance of RotateCertificateBody by calling from_dict on the json representation
        rotate_certificate_body_model_dict = RotateCertificateBody.from_dict(rotate_certificate_body_model_json).__dict__
        rotate_certificate_body_model2 = RotateCertificateBody(**rotate_certificate_body_model_dict)

        # Verify the model instances are equivalent
        assert rotate_certificate_body_model == rotate_certificate_body_model2

        # Convert model instance back to dict and verify no loss of data
        rotate_certificate_body_model_json2 = rotate_certificate_body_model.to_dict()
        assert rotate_certificate_body_model_json2 == rotate_certificate_body_model_json

class TestModel_RotatePublicCertBody():
    """
    Test Class for RotatePublicCertBody
    """

    def test_rotate_public_cert_body_serialization(self):
        """
        Test serialization/deserialization for RotatePublicCertBody
        """

        # Construct a json representation of a RotatePublicCertBody model
        rotate_public_cert_body_model_json = {}
        rotate_public_cert_body_model_json['rotate_keys'] = True

        # Construct a model instance of RotatePublicCertBody by calling from_dict on the json representation
        rotate_public_cert_body_model = RotatePublicCertBody.from_dict(rotate_public_cert_body_model_json)
        assert rotate_public_cert_body_model != False

        # Construct a model instance of RotatePublicCertBody by calling from_dict on the json representation
        rotate_public_cert_body_model_dict = RotatePublicCertBody.from_dict(rotate_public_cert_body_model_json).__dict__
        rotate_public_cert_body_model2 = RotatePublicCertBody(**rotate_public_cert_body_model_dict)

        # Verify the model instances are equivalent
        assert rotate_public_cert_body_model == rotate_public_cert_body_model2

        # Convert model instance back to dict and verify no loss of data
        rotate_public_cert_body_model_json2 = rotate_public_cert_body_model.to_dict()
        assert rotate_public_cert_body_model_json2 == rotate_public_cert_body_model_json

class TestModel_RotateUsernamePasswordSecretBody():
    """
    Test Class for RotateUsernamePasswordSecretBody
    """

    def test_rotate_username_password_secret_body_serialization(self):
        """
        Test serialization/deserialization for RotateUsernamePasswordSecretBody
        """

        # Construct a json representation of a RotateUsernamePasswordSecretBody model
        rotate_username_password_secret_body_model_json = {}
        rotate_username_password_secret_body_model_json['password'] = 'testString'

        # Construct a model instance of RotateUsernamePasswordSecretBody by calling from_dict on the json representation
        rotate_username_password_secret_body_model = RotateUsernamePasswordSecretBody.from_dict(rotate_username_password_secret_body_model_json)
        assert rotate_username_password_secret_body_model != False

        # Construct a model instance of RotateUsernamePasswordSecretBody by calling from_dict on the json representation
        rotate_username_password_secret_body_model_dict = RotateUsernamePasswordSecretBody.from_dict(rotate_username_password_secret_body_model_json).__dict__
        rotate_username_password_secret_body_model2 = RotateUsernamePasswordSecretBody(**rotate_username_password_secret_body_model_dict)

        # Verify the model instances are equivalent
        assert rotate_username_password_secret_body_model == rotate_username_password_secret_body_model2

        # Convert model instance back to dict and verify no loss of data
        rotate_username_password_secret_body_model_json2 = rotate_username_password_secret_body_model.to_dict()
        assert rotate_username_password_secret_body_model_json2 == rotate_username_password_secret_body_model_json

class TestModel_SecretPolicyRotationRotationPolicyRotation():
    """
    Test Class for SecretPolicyRotationRotationPolicyRotation
    """

    def test_secret_policy_rotation_rotation_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for SecretPolicyRotationRotationPolicyRotation
        """

        # Construct a json representation of a SecretPolicyRotationRotationPolicyRotation model
        secret_policy_rotation_rotation_policy_rotation_model_json = {}
        secret_policy_rotation_rotation_policy_rotation_model_json['interval'] = 1
        secret_policy_rotation_rotation_policy_rotation_model_json['unit'] = 'day'

        # Construct a model instance of SecretPolicyRotationRotationPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_policy_rotation_model = SecretPolicyRotationRotationPolicyRotation.from_dict(secret_policy_rotation_rotation_policy_rotation_model_json)
        assert secret_policy_rotation_rotation_policy_rotation_model != False

        # Construct a model instance of SecretPolicyRotationRotationPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_policy_rotation_model_dict = SecretPolicyRotationRotationPolicyRotation.from_dict(secret_policy_rotation_rotation_policy_rotation_model_json).__dict__
        secret_policy_rotation_rotation_policy_rotation_model2 = SecretPolicyRotationRotationPolicyRotation(**secret_policy_rotation_rotation_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert secret_policy_rotation_rotation_policy_rotation_model == secret_policy_rotation_rotation_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        secret_policy_rotation_rotation_policy_rotation_model_json2 = secret_policy_rotation_rotation_policy_rotation_model.to_dict()
        assert secret_policy_rotation_rotation_policy_rotation_model_json2 == secret_policy_rotation_rotation_policy_rotation_model_json

class TestModel_SecretPolicyRotationRotationPublicCertPolicyRotation():
    """
    Test Class for SecretPolicyRotationRotationPublicCertPolicyRotation
    """

    def test_secret_policy_rotation_rotation_public_cert_policy_rotation_serialization(self):
        """
        Test serialization/deserialization for SecretPolicyRotationRotationPublicCertPolicyRotation
        """

        # Construct a json representation of a SecretPolicyRotationRotationPublicCertPolicyRotation model
        secret_policy_rotation_rotation_public_cert_policy_rotation_model_json = {}
        secret_policy_rotation_rotation_public_cert_policy_rotation_model_json['auto_rotate'] = False
        secret_policy_rotation_rotation_public_cert_policy_rotation_model_json['rotate_keys'] = False

        # Construct a model instance of SecretPolicyRotationRotationPublicCertPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_public_cert_policy_rotation_model = SecretPolicyRotationRotationPublicCertPolicyRotation.from_dict(secret_policy_rotation_rotation_public_cert_policy_rotation_model_json)
        assert secret_policy_rotation_rotation_public_cert_policy_rotation_model != False

        # Construct a model instance of SecretPolicyRotationRotationPublicCertPolicyRotation by calling from_dict on the json representation
        secret_policy_rotation_rotation_public_cert_policy_rotation_model_dict = SecretPolicyRotationRotationPublicCertPolicyRotation.from_dict(secret_policy_rotation_rotation_public_cert_policy_rotation_model_json).__dict__
        secret_policy_rotation_rotation_public_cert_policy_rotation_model2 = SecretPolicyRotationRotationPublicCertPolicyRotation(**secret_policy_rotation_rotation_public_cert_policy_rotation_model_dict)

        # Verify the model instances are equivalent
        assert secret_policy_rotation_rotation_public_cert_policy_rotation_model == secret_policy_rotation_rotation_public_cert_policy_rotation_model2

        # Convert model instance back to dict and verify no loss of data
        secret_policy_rotation_rotation_public_cert_policy_rotation_model_json2 = secret_policy_rotation_rotation_public_cert_policy_rotation_model.to_dict()
        assert secret_policy_rotation_rotation_public_cert_policy_rotation_model_json2 == secret_policy_rotation_rotation_public_cert_policy_rotation_model_json

class TestModel_UsernamePasswordSecretMetadata():
    """
    Test Class for UsernamePasswordSecretMetadata
    """

    def test_username_password_secret_metadata_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretMetadata
        """

        # Construct a json representation of a UsernamePasswordSecretMetadata model
        username_password_secret_metadata_model_json = {}
        username_password_secret_metadata_model_json['id'] = 'b0283d74-0894-830b-f81d-1f115f67729f'
        username_password_secret_metadata_model_json['labels'] = ['dev', 'us-south']
        username_password_secret_metadata_model_json['name'] = 'example-secret'
        username_password_secret_metadata_model_json['description'] = 'Extended description for this secret.'
        username_password_secret_metadata_model_json['secret_group_id'] = 'f5283d74-9024-230a-b72c-1f115f61290f'
        username_password_secret_metadata_model_json['state'] = 0
        username_password_secret_metadata_model_json['state_description'] = 'Active'
        username_password_secret_metadata_model_json['secret_type'] = 'arbitrary'
        username_password_secret_metadata_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        username_password_secret_metadata_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        username_password_secret_metadata_model_json['created_by'] = 'ServiceId-cb258cb9-8de3-4ac0-9aec-b2b2d27ac976'
        username_password_secret_metadata_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        username_password_secret_metadata_model_json['versions_total'] = 1
        username_password_secret_metadata_model_json['expiration_date'] = "2030-04-01T09:30:00Z"

        # Construct a model instance of UsernamePasswordSecretMetadata by calling from_dict on the json representation
        username_password_secret_metadata_model = UsernamePasswordSecretMetadata.from_dict(username_password_secret_metadata_model_json)
        assert username_password_secret_metadata_model != False

        # Construct a model instance of UsernamePasswordSecretMetadata by calling from_dict on the json representation
        username_password_secret_metadata_model_dict = UsernamePasswordSecretMetadata.from_dict(username_password_secret_metadata_model_json).__dict__
        username_password_secret_metadata_model2 = UsernamePasswordSecretMetadata(**username_password_secret_metadata_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_metadata_model == username_password_secret_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_metadata_model_json2 = username_password_secret_metadata_model.to_dict()
        assert username_password_secret_metadata_model_json2 == username_password_secret_metadata_model_json

class TestModel_UsernamePasswordSecretResource():
    """
    Test Class for UsernamePasswordSecretResource
    """

    def test_username_password_secret_resource_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretResource
        """

        # Construct a json representation of a UsernamePasswordSecretResource model
        username_password_secret_resource_model_json = {}
        username_password_secret_resource_model_json['id'] = 'testString'
        username_password_secret_resource_model_json['name'] = 'testString'
        username_password_secret_resource_model_json['description'] = 'testString'
        username_password_secret_resource_model_json['secret_group_id'] = 'testString'
        username_password_secret_resource_model_json['labels'] = ['testString']
        username_password_secret_resource_model_json['state'] = 0
        username_password_secret_resource_model_json['state_description'] = 'Active'
        username_password_secret_resource_model_json['secret_type'] = 'arbitrary'
        username_password_secret_resource_model_json['crn'] = 'crn:v1:bluemix:public:secrets-manager:<region>:a/<account-id>:<service-instance>:secret:<secret-id>'
        username_password_secret_resource_model_json['creation_date'] = "2018-04-12T23:20:50.520000Z"
        username_password_secret_resource_model_json['created_by'] = 'testString'
        username_password_secret_resource_model_json['last_update_date'] = "2018-04-12T23:20:50.520000Z"
        username_password_secret_resource_model_json['versions_total'] = 1
        username_password_secret_resource_model_json['versions'] = [{}]
        username_password_secret_resource_model_json['username'] = 'user123'
        username_password_secret_resource_model_json['password'] = 'rainy-cloudy-coffee-book'
        username_password_secret_resource_model_json['secret_data'] = { 'foo': 'bar' }
        username_password_secret_resource_model_json['expiration_date'] = "2030-04-01T09:30:00Z"
        username_password_secret_resource_model_json['next_rotation_date'] = "2025-04-12T23:20:50.520000Z"

        # Construct a model instance of UsernamePasswordSecretResource by calling from_dict on the json representation
        username_password_secret_resource_model = UsernamePasswordSecretResource.from_dict(username_password_secret_resource_model_json)
        assert username_password_secret_resource_model != False

        # Construct a model instance of UsernamePasswordSecretResource by calling from_dict on the json representation
        username_password_secret_resource_model_dict = UsernamePasswordSecretResource.from_dict(username_password_secret_resource_model_json).__dict__
        username_password_secret_resource_model2 = UsernamePasswordSecretResource(**username_password_secret_resource_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_resource_model == username_password_secret_resource_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_resource_model_json2 = username_password_secret_resource_model.to_dict()
        assert username_password_secret_resource_model_json2 == username_password_secret_resource_model_json

class TestModel_UsernamePasswordSecretVersionMetadata():
    """
    Test Class for UsernamePasswordSecretVersionMetadata
    """

    def test_username_password_secret_version_metadata_serialization(self):
        """
        Test serialization/deserialization for UsernamePasswordSecretVersionMetadata
        """

        # Construct a json representation of a UsernamePasswordSecretVersionMetadata model
        username_password_secret_version_metadata_model_json = {}
        username_password_secret_version_metadata_model_json['id'] = '4a0225e9-17a0-46c1-ace7-f25bcf4237d4'
        username_password_secret_version_metadata_model_json['creation_date'] = "2019-01-01T12:00:00Z"
        username_password_secret_version_metadata_model_json['created_by'] = 'testString'
        username_password_secret_version_metadata_model_json['auto_rotated'] = True

        # Construct a model instance of UsernamePasswordSecretVersionMetadata by calling from_dict on the json representation
        username_password_secret_version_metadata_model = UsernamePasswordSecretVersionMetadata.from_dict(username_password_secret_version_metadata_model_json)
        assert username_password_secret_version_metadata_model != False

        # Construct a model instance of UsernamePasswordSecretVersionMetadata by calling from_dict on the json representation
        username_password_secret_version_metadata_model_dict = UsernamePasswordSecretVersionMetadata.from_dict(username_password_secret_version_metadata_model_json).__dict__
        username_password_secret_version_metadata_model2 = UsernamePasswordSecretVersionMetadata(**username_password_secret_version_metadata_model_dict)

        # Verify the model instances are equivalent
        assert username_password_secret_version_metadata_model == username_password_secret_version_metadata_model2

        # Convert model instance back to dict and verify no loss of data
        username_password_secret_version_metadata_model_json2 = username_password_secret_version_metadata_model.to_dict()
        assert username_password_secret_version_metadata_model_json2 == username_password_secret_version_metadata_model_json


# endregion
##############################################################################
# End of Model Tests
##############################################################################
