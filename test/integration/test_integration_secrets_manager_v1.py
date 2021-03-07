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
Integration Tests for SecretsManagerV1
"""
import os
import time
import unittest

from ibm_cloud_sdk_core.authenticators.iam_authenticator import IAMAuthenticator
from ibm_cloud_sdk_core.api_exception import ApiException
from ibm_secrets_manager_sdk.secrets_manager_v1 import *

secretsManager = SecretsManagerV1(
    authenticator=IAMAuthenticator(apikey=os.environ.get('SECRETS_MANAGER_API_APIKEY'), url=os.environ.get('AUTH_URL'))
)

secretsManager.set_service_url(os.environ.get('SERVICE_URL'))

class TestArbitrarySecret(unittest.TestCase):

    def test_create_and_delete_secret(self):
        # create arbitrary secret
        response = secretsManager.create_secret(
            'arbitrary',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated', 'labels': ['label1', 'label2'],
              'expiration_date': generate_expiration_date(), 'payload': 'secret-data'}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        # get arbitrary secret
        response = secretsManager.get_secret(
            'arbitrary',
            secretId
        )
        assert response.status_code == 200
        assert response.result['resources'][0]['secret_data']['payload'] == 'secret-data'
        # delete arbitrary secret
        response = secretsManager.delete_secret(
            'arbitrary',
            secretId
        )
        assert response.status_code == 204

    def test_secret_group(self):
        # create a secret group
        response = secretsManager.create_secret_group(
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret.group+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated'}]
        )
        assert response.status_code == 200
        secretGroupId = response.result['resources'][0]['id']
        # create username_password secret and associate it with our secret group
        response = secretsManager.create_secret(
            'username_password',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated', 'labels': ['label1'],
              'expiration_date': generate_expiration_date(), 'secret_group_id': secretGroupId, 'username': 'test_user',
              'password': 'test_password'}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        response = secretsManager.get_secret(
            'username_password',
            secretId
        )
        assert response.status_code == 200
        # delete username_password secret
        response = secretsManager.delete_secret(
            'username_password',
            secretId
        )
        assert response.status_code == 204
        # delete the secret group
        response = secretsManager.delete_secret_group(
            secretGroupId
        )
        assert response.status_code == 204

    def test_secret_rotation_policy(self):
        # create username_password secret
        response = secretsManager.create_secret(
            'username_password',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated', 'labels': ['label1'],
              'expiration_date': generate_expiration_date(), 'username': 'test_user',
              'password': 'test_password'}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        # Create a rotation policy for the username_password secret type we have just created
        response = secretsManager.put_policy(
            'username_password',
            secretId,
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret.policy+json', 'collection_total': 1},
            [{'type': 'application/vnd.ibm.secrets-manager.secret.policy+json',
              'rotation': {'interval': 1, 'unit': 'month'}}],
            policy='rotation'
        )
        assert response.status_code == 200
        # get username_password secret
        response = secretsManager.get_secret(
            'username_password',
            secretId
        )
        assert response.status_code == 200
        assert response.result['resources'][0]['secret_data']['username'] == 'test_user'
        assert response.result['resources'][0]['secret_data']['password'] == 'test_password'
        assert 'next_rotation_date' in response.result['resources'][0]
        # delete username_password secret
        response = secretsManager.delete_secret(
            'username_password',
            secretId
        )
        assert response.status_code == 204

    def test_create_a_secret_with_the_same_name(self):
        secretName = 'conflict_integration_test_secret'
        # create arbitrary secret
        response = secretsManager.create_secret(
            'arbitrary',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': secretName, 'description': 'Integration test generated', 'payload': 'secret-data'}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        # now reuse the same secret name under the same secret type, should result in a conflict error.
        try:
            response = secretsManager.create_secret(
                'arbitrary',
                {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
                [{'name': secretName, 'description': 'Integration test generated', 'payload': 'secret-data'}]
            )
        except ApiException as err:
            assert err.code == 409
            assert err.message == 'Conflict'
        finally:
            # delete arbitrary secret
            response = secretsManager.delete_secret(
                'arbitrary',
                secretId
            )
            assert response.status_code == 204


def generate_name():
    return 'test-integration-' + str(int(time.time()))


def generate_expiration_date():
    now = datetime.utcnow()
    expiration = now.replace(year=now.year + 10)
    return expiration.isoformat('T') + 'Z'
