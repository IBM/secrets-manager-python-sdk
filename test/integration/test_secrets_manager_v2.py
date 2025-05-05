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
Integration Tests for SecretsManagerV2
"""

from ibm_cloud_sdk_core import *
import os
import pytest
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

# Config file name
config_file = 'secrets_manager_v2.env'

# Variables to hold link values
configuration_name_for_get_configuration_link = None
secret_group_id_for_get_secret_group_link = None
secret_id_for_create_secret_version_link = None
secret_id_for_create_secret_version_locks_link = None
secret_id_for_get_secret_link = None
secret_id_for_get_secret_version_link = None
secret_id_for_list_secret_locks_link = None
secret_id_for_list_secret_version_locks_link = None
secret_name_link = None
secret_version_id_for_create_secret_version_locks_link = None
secret_version_id_for_delete_secret_version_locks_link = None
secret_version_id_for_get_secret_version_link = None
secret_version_id_for_get_secret_version_metadata_link = None
secret_version_id_for_list_secret_version_locks_link = None
secret_version_id_for_update_secret_version_metadata_link = None


class TestSecretsManagerV2:
    """
    Integration Test Class for SecretsManagerV2
    """

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            cls.secrets_manager_service = SecretsManagerV2.new_instance(
            )
            assert cls.secrets_manager_service is not None

            cls.config = read_external_sources(SecretsManagerV2.DEFAULT_SERVICE_NAME)
            assert cls.config is not None

            cls.secrets_manager_service.enable_retries()

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_create_secret_group(self):
        global secret_group_id_for_get_secret_group_link

        response = self.secrets_manager_service.create_secret_group(
            name='my-secret-group',
            description='Extended description for this group.',
        )

        assert response.get_status_code() == 201
        secret_group = response.get_result()
        assert secret_group is not None

        secret_group_id_for_get_secret_group_link = secret_group['id']

    @needscredentials
    def test_create_secret(self):
        global secret_id_for_get_secret_link
        global secret_id_for_get_secret_version_link

        # Construct a dict representation of a ArbitrarySecretPrototype model
        secret_prototype_model = {
            'custom_metadata': {'metadata_custom_key': 'metadata_custom_value'},
            'description': 'Description of my arbitrary secret.',
            'expiration_date': '2030-10-05T11:49:42Z',
            'labels': ['dev', 'us-south'],
            'name': 'example-arbitrary-secret',
            'secret_group_id': 'default',
            'secret_type': 'arbitrary',
            'payload': 'secret-data',
            'version_custom_metadata': {'custom_version_key': 'custom_version_value'},
        }

        response = self.secrets_manager_service.create_secret(
            secret_prototype=secret_prototype_model,
        )

        assert response.get_status_code() == 201
        secret = response.get_result()
        assert secret is not None

        secret_id_for_get_secret_link = secret['id']
        secret_id_for_get_secret_version_link = secret['id']

    @needscredentials
    def test_update_secret_metadata(self):
        global secret_name_link

        # Construct a dict representation of a ArbitrarySecretMetadataPatch model
        secret_metadata_patch_model = {
            'name': 'updated-arbitrary-secret-name-example',
            'description': 'updated Arbitrary Secret description',
            'labels': ['dev', 'us-south'],
            'custom_metadata': {'metadata_custom_key': 'metadata_custom_value'},
            'expiration_date': '2033-04-12T23:20:50.520Z',
        }

        response = self.secrets_manager_service.update_secret_metadata(
            id=secret_id_for_get_secret_link,
            secret_metadata_patch=secret_metadata_patch_model,
        )

        assert response.get_status_code() == 200
        secret_metadata = response.get_result()
        assert secret_metadata is not None

        secret_name_link = secret_metadata['name']

    @needscredentials
    def test_list_secret_versions(self):
        global secret_version_id_for_get_secret_version_link
        global secret_id_for_create_secret_version_link
        global secret_version_id_for_get_secret_version_metadata_link
        global secret_version_id_for_update_secret_version_metadata_link
        global secret_id_for_create_secret_version_locks_link
        global secret_version_id_for_create_secret_version_locks_link
        global secret_version_id_for_delete_secret_version_locks_link

        response = self.secrets_manager_service.list_secret_versions(
            secret_id=secret_id_for_get_secret_link,
        )

        assert response.get_status_code() == 200
        secret_version_metadata_collection = response.get_result()
        assert secret_version_metadata_collection is not None

        secret_version_id_for_get_secret_version_link = secret_version_metadata_collection['versions'][0]['id']
        secret_id_for_create_secret_version_link = secret_version_metadata_collection['versions'][0]['secret_id']
        secret_version_id_for_get_secret_version_metadata_link = secret_version_metadata_collection['versions'][0]['id']
        secret_version_id_for_update_secret_version_metadata_link = secret_version_metadata_collection['versions'][0]['id']
        secret_id_for_create_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['secret_id']
        secret_version_id_for_create_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['id']
        secret_version_id_for_delete_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['id']

    @needscredentials
    def test_create_secret_locks_bulk(self):
        global secret_id_for_list_secret_locks_link
        global secret_id_for_list_secret_version_locks_link
        global secret_version_id_for_list_secret_version_locks_link

        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {
            'name': 'lock-example-1',
            'description': 'lock for consumer 1',
            'attributes': {'key': 'value'},
        }

        response = self.secrets_manager_service.create_secret_locks_bulk(
            id=secret_id_for_get_secret_link,
            locks=[secret_lock_prototype_model],
            mode='remove_previous',
        )

        assert response.get_status_code() == 201
        secret_locks = response.get_result()
        assert secret_locks is not None

        secret_id_for_list_secret_locks_link = secret_locks['secret_id']
        secret_id_for_list_secret_version_locks_link = secret_locks['secret_id']
        secret_version_id_for_list_secret_version_locks_link = secret_locks['versions'][0]['version_id']

    @needscredentials
    def test_create_configuration(self):
        global configuration_name_for_get_configuration_link

        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPrototype model
        configuration_prototype_model = {
            'config_type': 'public_cert_configuration_dns_cloud_internet_services',
            'name': 'example-cloud-internet-services-config',
            'cloud_internet_services_apikey': '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ',
            'cloud_internet_services_crn': 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::',
        }

        response = self.secrets_manager_service.create_configuration(
            configuration_prototype=configuration_prototype_model,
        )

        assert response.get_status_code() == 201
        configuration = response.get_result()
        assert configuration is not None

        configuration_name_for_get_configuration_link = configuration['name']

    @needscredentials
    def test_list_secret_groups(self):
        response = self.secrets_manager_service.list_secret_groups()

        assert response.get_status_code() == 200
        secret_group_collection = response.get_result()
        assert secret_group_collection is not None

    @needscredentials
    def test_get_secret_group(self):
        response = self.secrets_manager_service.get_secret_group(
            id=secret_group_id_for_get_secret_group_link,
        )

        assert response.get_status_code() == 200
        secret_group = response.get_result()
        assert secret_group is not None

    @needscredentials
    def test_update_secret_group(self):
        # Construct a dict representation of a SecretGroupPatch model
        secret_group_patch_model = {
            'name': 'my-secret-group',
            'description': 'Extended description for this group.',
        }

        response = self.secrets_manager_service.update_secret_group(
            id=secret_group_id_for_get_secret_group_link,
            secret_group_patch=secret_group_patch_model,
        )

        assert response.get_status_code() == 200
        secret_group = response.get_result()
        assert secret_group is not None

    @needscredentials
    def test_list_secrets(self):
        response = self.secrets_manager_service.list_secrets(
            offset=0,
            limit=200,
            sort='created_at',
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            secret_types=['arbitrary', 'kv'],
            match_all_labels=['dev', 'us-south'],
        )

        assert response.get_status_code() == 200
        secret_metadata_paginated_collection = response.get_result()
        assert secret_metadata_paginated_collection is not None

    @needscredentials
    def test_list_secrets_with_pager(self):
        all_results = []

        # Test get_next().
        pager = SecretsPager(
            client=self.secrets_manager_service,
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

        # Test get_all().
        pager = SecretsPager(
            client=self.secrets_manager_service,
            limit=10,
            sort='created_at',
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            secret_types=['arbitrary', 'kv'],
            match_all_labels=['dev', 'us-south'],
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_secrets() returned a total of {len(all_results)} items(s) using SecretsPager.')

    @needscredentials
    def test_get_secret(self):
        response = self.secrets_manager_service.get_secret(
            id=secret_id_for_get_secret_link,
        )

        assert response.get_status_code() == 200
        secret = response.get_result()
        assert secret is not None

    @needscredentials
    def test_get_secret_metadata(self):
        response = self.secrets_manager_service.get_secret_metadata(
            id=secret_id_for_get_secret_link,
        )

        assert response.get_status_code() == 200
        secret_metadata = response.get_result()
        assert secret_metadata is not None

  # The integration test for create_secret_action has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_create_secret_action(self):

    @needscredentials
    def test_get_secret_by_name_type(self):
        response = self.secrets_manager_service.get_secret_by_name_type(
            secret_type='arbitrary',
            name=secret_name_link,
            secret_group_name='default',
        )

        assert response.get_status_code() == 200
        secret = response.get_result()
        assert secret is not None

    @needscredentials
    def test_create_secret_version(self):
        # Construct a dict representation of a ArbitrarySecretVersionPrototype model
        secret_version_prototype_model = {
            'payload': 'updated secret credentials',
            'custom_metadata': {'metadata_custom_key': 'metadata_custom_value'},
            'version_custom_metadata': {'custom_version_key': 'custom_version_value'},
        }

        response = self.secrets_manager_service.create_secret_version(
            secret_id=secret_id_for_get_secret_link,
            secret_version_prototype=secret_version_prototype_model,
        )

        assert response.get_status_code() == 201
        secret_version = response.get_result()
        assert secret_version is not None

    @needscredentials
    def test_get_secret_version(self):
        response = self.secrets_manager_service.get_secret_version(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
        )

        assert response.get_status_code() == 200
        secret_version = response.get_result()
        assert secret_version is not None

    @needscredentials
    def test_get_secret_version_metadata(self):
        response = self.secrets_manager_service.get_secret_version_metadata(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
        )

        assert response.get_status_code() == 200
        secret_version_metadata = response.get_result()
        assert secret_version_metadata is not None

    @needscredentials
    def test_update_secret_version_metadata(self):
        # Construct a dict representation of a SecretVersionMetadataPatch model
        secret_version_metadata_patch_model = {
            'version_custom_metadata': {'key': 'value'},
        }

        response = self.secrets_manager_service.update_secret_version_metadata(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            secret_version_metadata_patch=secret_version_metadata_patch_model,
        )

        assert response.get_status_code() == 200
        secret_version_metadata = response.get_result()
        assert secret_version_metadata is not None

  # The integration test for create_secret_version_action has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_create_secret_version_action(self):

  # The integration test for list_secret_tasks has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_list_secret_tasks(self):

  # The integration test for get_secret_task has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_get_secret_task(self):

  # The integration test for replace_secret_task has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_replace_secret_task(self):

    @needscredentials
    def test_list_secrets_locks(self):
        response = self.secrets_manager_service.list_secrets_locks(
            offset=0,
            limit=200,
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
        )

        assert response.get_status_code() == 200
        secrets_locks_paginated_collection = response.get_result()
        assert secrets_locks_paginated_collection is not None

    @needscredentials
    def test_list_secrets_locks_with_pager(self):
        all_results = []

        # Test get_next().
        pager = SecretsLocksPager(
            client=self.secrets_manager_service,
            limit=10,
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)

        # Test get_all().
        pager = SecretsLocksPager(
            client=self.secrets_manager_service,
            limit=10,
            search='example',
            groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_secrets_locks() returned a total of {len(all_results)} items(s) using SecretsLocksPager.')

    @needscredentials
    def test_list_secret_locks(self):
        response = self.secrets_manager_service.list_secret_locks(
            id=secret_id_for_get_secret_link,
            offset=0,
            limit=25,
            sort='name',
            search='example',
        )

        assert response.get_status_code() == 200
        secret_locks_paginated_collection = response.get_result()
        assert secret_locks_paginated_collection is not None

    @needscredentials
    def test_list_secret_locks_with_pager(self):
        all_results = []

        # Test get_next().
        pager = SecretLocksPager(
            client=self.secrets_manager_service,
            id=secret_id_for_get_secret_link,
            limit=10,
            sort='name',
            search='example',
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)

        # Test get_all().
        pager = SecretLocksPager(
            client=self.secrets_manager_service,
            id=secret_id_for_get_secret_link,
            limit=10,
            sort='name',
            search='example',
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_secret_locks() returned a total of {len(all_results)} items(s) using SecretLocksPager.')

    @needscredentials
    def test_create_secret_version_locks_bulk(self):
        # Construct a dict representation of a SecretLockPrototype model
        secret_lock_prototype_model = {
            'name': 'lock-example-1',
            'description': 'lock for consumer 1',
            'attributes': {'key': 'value'},
        }

        response = self.secrets_manager_service.create_secret_version_locks_bulk(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            locks=[secret_lock_prototype_model],
            mode='remove_previous',
        )

        assert response.get_status_code() == 201
        secret_locks = response.get_result()
        assert secret_locks is not None

    @needscredentials
    def test_list_secret_version_locks(self):
        response = self.secrets_manager_service.list_secret_version_locks(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            offset=0,
            limit=25,
            sort='name',
            search='example',
        )

        assert response.get_status_code() == 200
        secret_version_locks_paginated_collection = response.get_result()
        assert secret_version_locks_paginated_collection is not None

    @needscredentials
    def test_list_secret_version_locks_with_pager(self):
        all_results = []

        # Test get_next().
        pager = SecretVersionLocksPager(
            client=self.secrets_manager_service,
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            limit=10,
            sort='name',
            search='example',
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)

        # Test get_all().
        pager = SecretVersionLocksPager(
            client=self.secrets_manager_service,
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            limit=10,
            sort='name',
            search='example',
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_secret_version_locks() returned a total of {len(all_results)} items(s) using SecretVersionLocksPager.')

    @needscredentials
    def test_list_configurations(self):
        response = self.secrets_manager_service.list_configurations(
            offset=0,
            limit=200,
            sort='config_type',
            search='example',
            secret_types=['iam_credentials', 'public_cert', 'private_cert', 'custom_credentials'],
        )

        assert response.get_status_code() == 200
        configuration_metadata_paginated_collection = response.get_result()
        assert configuration_metadata_paginated_collection is not None

    @needscredentials
    def test_list_configurations_with_pager(self):
        all_results = []

        # Test get_next().
        pager = ConfigurationsPager(
            client=self.secrets_manager_service,
            limit=10,
            sort='config_type',
            search='example',
            secret_types=['iam_credentials', 'public_cert', 'private_cert', 'custom_credentials'],
        )
        while pager.has_next():
            next_page = pager.get_next()
            assert next_page is not None
            all_results.extend(next_page)

        # Test get_all().
        pager = ConfigurationsPager(
            client=self.secrets_manager_service,
            limit=10,
            sort='config_type',
            search='example',
            secret_types=['iam_credentials', 'public_cert', 'private_cert', 'custom_credentials'],
        )
        all_items = pager.get_all()
        assert all_items is not None

        assert len(all_results) == len(all_items)
        print(f'\nlist_configurations() returned a total of {len(all_results)} items(s) using ConfigurationsPager.')

    @needscredentials
    def test_get_configuration(self):
        response = self.secrets_manager_service.get_configuration(
            name=configuration_name_for_get_configuration_link,
            x_sm_accept_configuration_type='public_cert_configuration_dns_cloud_internet_services',
        )

        assert response.get_status_code() == 200
        configuration = response.get_result()
        assert configuration is not None

    @needscredentials
    def test_update_configuration(self):
        # Construct a dict representation of a PublicCertificateConfigurationDNSCloudInternetServicesPatch model
        configuration_patch_model = {
            'cloud_internet_services_apikey': '5ipu_ykv0PMp2MhxQnDMn7VzrkSlBwi3BOI8uthi_EXZ',
            'cloud_internet_services_crn': 'crn:v1:bluemix:public:internet-svcs:global:a/128e84fcca45c1224aae525d31ef2b52:009a0357-1460-42b4-b903-10580aba7dd8::',
        }

        response = self.secrets_manager_service.update_configuration(
            name=configuration_name_for_get_configuration_link,
            configuration_patch=configuration_patch_model,
            x_sm_accept_configuration_type='public_cert_configuration_dns_cloud_internet_services',
        )

        assert response.get_status_code() == 200
        configuration = response.get_result()
        assert configuration is not None

  # The integration test for create_configuration_action has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_create_configuration_action(self):

    @needscredentials
    def test_create_notifications_registration(self):
        response = self.secrets_manager_service.create_notifications_registration(
            event_notifications_instance_crn='crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::',
            event_notifications_source_name='My Secrets Manager',
            event_notifications_source_description='Optional description of this source in an Event Notifications instance.',
        )

        assert response.get_status_code() == 201
        notifications_registration = response.get_result()
        assert notifications_registration is not None

    @needscredentials
    def test_get_notifications_registration(self):
        response = self.secrets_manager_service.get_notifications_registration()

        assert response.get_status_code() == 200
        notifications_registration = response.get_result()
        assert notifications_registration is not None

  # The integration test for get_notifications_registration_test has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_get_notifications_registration_test(self):

    @needscredentials
    def test_delete_secret_group(self):
        response = self.secrets_manager_service.delete_secret_group(
            id=secret_group_id_for_get_secret_group_link,
        )

        assert response.get_status_code() == 204

  # The integration test for delete_secret_version_data has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_delete_secret_version_data(self):

    @needscredentials
    def test_delete_secret_locks_bulk(self):
        response = self.secrets_manager_service.delete_secret_locks_bulk(
            id=secret_id_for_get_secret_link,
            name=['lock-example-1'],
        )

        assert response.get_status_code() == 200
        secret_locks = response.get_result()
        assert secret_locks is not None

    @needscredentials
    def test_delete_secret_version_locks_bulk(self):
        response = self.secrets_manager_service.delete_secret_version_locks_bulk(
            secret_id=secret_id_for_get_secret_link,
            id=secret_version_id_for_get_secret_version_link,
            name=['lock-example-1'],
        )

        assert response.get_status_code() == 200
        secret_locks = response.get_result()
        assert secret_locks is not None

    @needscredentials
    def test_delete_secret(self):
        response = self.secrets_manager_service.delete_secret(
            id=secret_id_for_get_secret_link,
            force_delete=False,
        )

        assert response.get_status_code() == 204

  # The integration test for delete_secret_task has been explicitly excluded from generation.
  # A test for this operation must be developed manually.
  # @needscredentials
  # def test_delete_secret_task(self):

    @needscredentials
    def test_delete_configuration(self):
        response = self.secrets_manager_service.delete_configuration(
            name=configuration_name_for_get_configuration_link,
            x_sm_accept_configuration_type='public_cert_configuration_dns_cloud_internet_services',
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_delete_notifications_registration(self):
        response = self.secrets_manager_service.delete_notifications_registration()

        assert response.get_status_code() == 204
