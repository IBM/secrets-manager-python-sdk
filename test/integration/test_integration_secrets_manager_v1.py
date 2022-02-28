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

    def test_create_and_delete_kv_secret(self):
        # create kv secret
        response = secretsManager.create_secret(
            'kv',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated', 'labels': ['label1', 'label2'],
              'payload': {"foo": "data"}}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        # get kv secret
        response = secretsManager.get_secret(
            'kv',
            secretId
        )
        assert response.status_code == 200
        assert response.result['resources'][0]['secret_data']['payload'] == {"foo": "data"}
        # delete kv secret
        response = secretsManager.delete_secret(
            'kv',
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
            assert err.message == 'A secret with the same name already exists: {}'.format(secretName)
        finally:
            # delete arbitrary secret
            response = secretsManager.delete_secret(
                'arbitrary',
                secretId
            )
            assert response.status_code == 204


class TestPublicCertSecret(unittest.TestCase):

    def test_create_configs_and_order_certificate(self):
        ca_config_name = generate_name() + '-ca'

        response = secretsManager.create_config_element(
            'public_cert', 'certificate_authorities', ca_config_name, 'letsencrypt-stage', {
                'private_key': os.environ.get('CA_CONFIG_PRIVATE_KEY').replace("\\n", "\n"),
            })

        assert response.status_code == 201

        dns_config_name = generate_name() + '-dns'

        response = secretsManager.create_config_element(
            'public_cert', 'dns_providers', dns_config_name, 'cis', {
                "cis_crn": os.environ.get("DNS_CONFIG_CRN"),
                "cis_apikey": os.environ.get("DNS_CONFIG_API_KEY"),
            })

        assert response.status_code == 201

        response = secretsManager.create_secret(
            'public_cert',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [
                {
                    'name': generate_name(),
                    'description': 'Integration test generated',
                    'labels': ['label1', 'label2'],
                    'common_name': 'integration.secrets-manager.test.appdomain.cloud',
                    'alt_names': ['integration2.secrets-manager.test.appdomain.cloud'],
                    'key_algorithm': 'RSA2048',
                    'ca': ca_config_name,
                    'dns': dns_config_name,
                    'rotation': {
                        'auto_rotate': False,
                        'rotate_keys': False
                    }
                }]
        )
        assert response.status_code == 202
        secret_id = response.result['resources'][0]['id']

    def test_create_get_list_delete_configs(self):
        ca_config_name = generate_name() + '-ca'

        response = secretsManager.create_config_element(
            'public_cert', 'certificate_authorities', ca_config_name, 'letsencrypt-stage', {
                'private_key': os.environ.get('CA_CONFIG_PRIVATE_KEY').replace("\\n", "\n"),
            })

        assert response.status_code == 201

        dns_config_name = generate_name() + '-dns'

        response = secretsManager.create_config_element(
            'public_cert', 'dns_providers', dns_config_name, 'cis', {
                "cis_crn": os.environ.get("DNS_CONFIG_CRN"),
                "cis_apikey": os.environ.get("DNS_CONFIG_API_KEY"),
            })

        assert response.status_code == 201

        response = secretsManager.get_config_element(
            dns_config_name, 'public_cert', 'dns_providers')

        assert response.status_code == 200

        response = secretsManager.get_config_element(
            ca_config_name, 'public_cert', 'certificate_authorities')

        assert response.status_code == 200

        response = secretsManager.get_config('public_cert')

        assert response.status_code == 200

        assert response.result['resources'][0]['dns_providers'] is not None
        assert response.result['resources'][0]['certificate_authorities'] is not None

        response = secretsManager.delete_config_element(
            ca_config_name, 'public_cert', 'certificate_authorities')

        assert response.status_code == 204

        response = secretsManager.delete_config_element(
            dns_config_name, 'public_cert', 'dns_providers')

        assert response.status_code == 204


class TestUsernamePasswordSecret(unittest.TestCase):

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


class TestImportedCertSecret(unittest.TestCase):

    def test_create_get_delete_secret(self):
        testCertificate = '-----BEGIN CERTIFICATE-----\r' \
                          '\nMIICsDCCAhmgAwIBAgIJALrogcLQxAOqMA0GCSqGSIb3DQEBCwUAMHExCzAJBgNV\r' \
                          '\nBAYTAnVzMREwDwYDVQQIDAh1cy1zb3V0aDEPMA0GA1UEBwwGRGFsLTEwMQwwCgYD\r' \
                          '\nVQQKDANJQk0xEzARBgNVBAsMCkNsb3VkQ2VydHMxGzAZBgNVBAMMEiouY2VydG1n\r' \
                          '\nbXQtZGV2LmNvbTAeFw0xODA0MjUwODM5NTlaFw00NTA5MTAwODM5NTlaMHExCzAJ\r' \
                          '\nBgNVBAYTAnVzMREwDwYDVQQIDAh1cy1zb3V0aDEPMA0GA1UEBwwGRGFsLTEwMQww\r' \
                          '\nCgYDVQQKDANJQk0xEzARBgNVBAsMCkNsb3VkQ2VydHMxGzAZBgNVBAMMEiouY2Vy\r' \
                          '\ndG1nbXQtZGV2LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAmy/4uEEw\r\nAn75rBuAIv5zi' \
                          '+1b2ycUnlw94x3QzYtY3QHQysFu73U3rczVHOsQNd9VIoC0z8py\r' \
                          '\npMZZu7W6dv6cjOSXlpiLfd7Y9TWzO43mNUH0qrnFpSgXM9ZXN3PJWjmTH3yxAsdK\r' \
                          '\nd5wtRdSv9AwrHWo8hHoTumoXYNMDuehyVJ8CAwEAAaNQME4wHQYDVR0OBBYEFMNC\r\nbcvQ' \
                          '+Smn8ikBDrMKhPc4C+f5MB8GA1UdIwQYMBaAFMNCbcvQ+Smn8ikBDrMKhPc4\r\nC' \
                          '+f5MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAFe2fCmzTcmCHeijV\r\nq0+EOvMRVNF' \
                          '/FTYyjb24gUGTbouZOkfv7JK94lAt/u5mPhpftYX+b1wUlkz0Kyl5\r\n4IgM0XXpcPYDdxQ87c0l/nAUF7Pi' \
                          '++u7CVmJBlclyDOL6AmBpUE0HyquQT4rSp/K\r\n+5qcqSxVjznd5XgQrWQGHLI2tnY=\r\n-----END ' \
                          'CERTIFICATE----- '
        testPrivateKey = '-----BEGIN PRIVATE KEY-----\r\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJsv+LhBMAJ' \
                         '++awb\r\ngCL+c4vtW9snFJ5cPeMd0M2LWN0B0MrBbu91N63M1RzrEDXfVSKAtM/KcqTGWbu1\r\nunb' \
                         '+nIzkl5aYi33e2PU1szuN5jVB9Kq5xaUoFzPWVzdzyVo5kx98sQLHSnecLUXU\r\nr' \
                         '/QMKx1qPIR6E7pqF2DTA7noclSfAgMBAAECgYBsFjd3rf+QXXvsQaM3vF4iIYoO\r\n0' \
                         '+NqgPihzUx3PQ0BsZgJAD0SD2ReawIsCBTcUNbtFxPYfjrnRTeOo/5hjujdq0ei\r\nx1PDh4qzDDPRxOdkCHjfMQb' \
                         '/FBNQvhSh+nQsylCm1qZeaOwgqiM8johDvQ8XLaql\r\n' \
                         '/uNcc1kGXHHd7hKQkQJBAMv04YfjtDxdfanrVtjz8Nm3QGklnAgmddRfY9AZB1Vw\r' \
                         '\nT4hpfvmRi0zOXn2KTaVjAcdqp0Irg+IyTQzd+q9dFG0CQQDCyVOEzUfLHotITqPy\r\nzN2EQ/e' \
                         '/YNnfsElBgNbL44V0Gy2vclLBt6hsvJrD0lSXHCo8aWplIvs2cRM/8uv3\r' \
                         '\nim27AkBrgcQTrgoGO72OgJeBumv9RuPzyLhLb4JylGl3eonsFkxF+l3MzVQhAzK5\r' \
                         '\nd9pf0CVS6TwK3AcjhyIoIyYNo8GtAkBUyi6A8Jr/4BvhLdpQJr2Ghc+ijxZIOQSq\r\nbtsRhcjh8bLBXJKJoNi' \
                         '//JmiBDyuSqRYB8s4mzGfUTl/7M6qwqdhAkEAnZEM+ZUV\r\nV0lZA18QsbwYHY1GVmaOi/dpZjS4ECl' \
                         '+7hbqhHfry88bgXzRKaITxe5Tss+lwQQ7\r\ncfLx+EZh+XOvRw==\r\n-----END PRIVATE KEY-----\r\n '
        # create certificate secret
        response = secretsManager.create_secret(
            'imported_cert',
            {'collection_type': 'application/vnd.ibm.secrets-manager.secret+json', 'collection_total': 1},
            [{'name': generate_name(), 'description': 'Integration test generated', 'labels': ['label1', 'label2'],
              'certificate': testCertificate, 'private_key': testPrivateKey}]
        )
        assert response.status_code == 200
        secretId = response.result['resources'][0]['id']
        # get certificate secret
        response = secretsManager.get_secret(
            'imported_cert',
            secretId
        )
        assert response.status_code == 200
        assert response.result['resources'][0]['secret_data']['certificate'] == testCertificate
        assert response.result['resources'][0]['secret_data']['private_key'] == testPrivateKey
        # delete certificate secret
        response = secretsManager.delete_secret(
            'imported_cert',
            secretId
        )
        assert response.status_code == 204


def generate_name():
    return 'test-integration-' + str(int(time.time()))


def generate_expiration_date():
    now = datetime.utcnow()
    expiration = now.replace(year=now.year + 10)
    return expiration.isoformat('T') + 'Z'
