# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2023.
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
Examples for SecretsManagerV2
"""

from ibm_cloud_sdk_core import ApiException, read_external_sources
import os
import pytest
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

#
# This file provides an example of how to use the secrets-manager service.
#
# The following configuration properties are assumed to be defined:
# SECRETS_MANAGER_URL=<service base url>
# SECRETS_MANAGER_AUTH_TYPE=iam
# SECRETS_MANAGER_APIKEY=<IAM apikey>
# SECRETS_MANAGER_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
#
# These configuration properties can be exported as environment variables, or stored
# in a configuration file and then:
# export IBM_CREDENTIALS_FILE=<name of configuration file>
#
config_file = 'secrets_manager_v2.env'

secrets_manager_service = None

config = None

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


##############################################################################
# Start of Examples for Service: SecretsManagerV2
##############################################################################
# region
class TestSecretsManagerV2Examples:
    """
    Example Test Class for SecretsManagerV2
    """

    @classmethod
    def setup_class(cls):
        global secrets_manager_service
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            # begin-common

            secrets_manager_service = SecretsManagerV2.new_instance(
            )

            # end-common
            assert secrets_manager_service is not None

            # Load the configuration
            global config
            config = read_external_sources(SecretsManagerV2.DEFAULT_SERVICE_NAME)

        print('Setup complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_create_secret_group_example(self):
        """
        create_secret_group request example
        """
        try:
            global secret_group_id_for_get_secret_group_link
            print('\ncreate_secret_group() result:')
            # begin-create_secret_group

            response = secrets_manager_service.create_secret_group(
                name='my-secret-group',
            )
            secret_group = response.get_result()

            print(json.dumps(secret_group, indent=2))

            # end-create_secret_group

            secret_group_id_for_get_secret_group_link = secret_group['id']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_example(self):
        """
        create_secret request example
        """
        try:
            global secret_id_for_get_secret_link
            global secret_id_for_get_secret_version_link
            print('\ncreate_secret() result:')
            # begin-create_secret

            secret_prototype_model = {
                'custom_metadata': {'metadata_custom_key':'metadata_custom_value'},
                'description': 'Description of my arbitrary secret.',
                'expiration_date': '2023-10-05T11:49:42Z',
                'labels': ['dev', 'us-south'],
                'name': 'example-arbitrary-secret',
                'secret_group_id': 'default',
                'secret_type': 'arbitrary',
                'payload': 'secret-data',
                'version_custom_metadata': {'custom_version_key':'custom_version_value'},
            }

            response = secrets_manager_service.create_secret(
                secret_prototype=secret_prototype_model,
            )
            secret = response.get_result()

            print(json.dumps(secret, indent=2))

            # end-create_secret

            secret_id_for_get_secret_link = secret['id']
            secret_id_for_get_secret_version_link = secret['id']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_update_secret_metadata_example(self):
        """
        update_secret_metadata request example
        """
        try:
            global secret_name_link
            print('\nupdate_secret_metadata() result:')
            # begin-update_secret_metadata

            secret_metadata_patch_model = {
                'name': 'updated-arbitrary-secret-name-example',
                'description': 'updated Arbitrary Secret description',
                'labels': ['dev', 'us-south'],
                'custom_metadata': {'metadata_custom_key':'metadata_custom_value'},
            }

            response = secrets_manager_service.update_secret_metadata(
                id=secret_id_for_get_secret_link,
                secret_metadata_patch=secret_metadata_patch_model,
            )
            secret_metadata = response.get_result()

            print(json.dumps(secret_metadata, indent=2))

            # end-update_secret_metadata

            secret_name_link = secret_metadata['name']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secret_versions_example(self):
        """
        list_secret_versions request example
        """
        try:
            global secret_version_id_for_get_secret_version_link
            global secret_id_for_create_secret_version_link
            global secret_version_id_for_get_secret_version_metadata_link
            global secret_version_id_for_update_secret_version_metadata_link
            global secret_id_for_create_secret_version_locks_link
            global secret_version_id_for_create_secret_version_locks_link
            global secret_version_id_for_delete_secret_version_locks_link
            print('\nlist_secret_versions() result:')
            # begin-list_secret_versions

            response = secrets_manager_service.list_secret_versions(
                secret_id=secret_id_for_get_secret_link,
            )
            secret_version_metadata_collection = response.get_result()

            print(json.dumps(secret_version_metadata_collection, indent=2))

            # end-list_secret_versions

            secret_version_id_for_get_secret_version_link = secret_version_metadata_collection['versions'][0]['id']
            secret_id_for_create_secret_version_link = secret_version_metadata_collection['versions'][0]['secret_id']
            secret_version_id_for_get_secret_version_metadata_link = secret_version_metadata_collection['versions'][0]['id']
            secret_version_id_for_update_secret_version_metadata_link = secret_version_metadata_collection['versions'][0]['id']
            secret_id_for_create_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['secret_id']
            secret_version_id_for_create_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['id']
            secret_version_id_for_delete_secret_version_locks_link = secret_version_metadata_collection['versions'][0]['id']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_locks_bulk_example(self):
        """
        create_secret_locks_bulk request example
        """
        try:
            global secret_id_for_list_secret_locks_link
            global secret_id_for_list_secret_version_locks_link
            global secret_version_id_for_list_secret_version_locks_link
            print('\ncreate_secret_locks_bulk() result:')
            # begin-create_secret_locks_bulk

            secret_lock_prototype_model = {
                'name': 'lock-example-1',
                'description': 'lock for consumer 1',
                'attributes': {'key':'value'},
            }

            response = secrets_manager_service.create_secret_locks_bulk(
                id=secret_id_for_get_secret_link,
                locks=[secret_lock_prototype_model],
            )
            secret_locks = response.get_result()

            print(json.dumps(secret_locks, indent=2))

            # end-create_secret_locks_bulk

            secret_id_for_list_secret_locks_link = secret_locks['secret_id']
            secret_id_for_list_secret_version_locks_link = secret_locks['secret_id']
            secret_version_id_for_list_secret_version_locks_link = secret_locks['versions'][0]['version_id']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_configuration_example(self):
        """
        create_configuration request example
        """
        try:
            global configuration_name_for_get_configuration_link
            print('\ncreate_configuration() result:')
            # begin-create_configuration

            configuration_prototype_model = {
                'config_type': 'private_cert_configuration_root_ca',
                'name': 'example-root-CA',
                'max_ttl': '43830h',
                'crl_expiry': '72h',
                'crl_disable': False,
                'crl_distribution_points_encoded': True,
                'issuing_certificates_urls_encoded': True,
                'common_name': 'example.com',
                'alt_names': ['alt-name-1', 'alt-name-2'],
                'ip_sans': '127.0.0.1',
                'uri_sans': 'https://www.example.com/test',
                'other_sans': ['1.2.3.5.4.3.201.10.4.3;utf8:test@example.com'],
                'ttl': '2190h',
                'format': 'pem',
                'private_key_format': 'der',
                'key_type': 'rsa',
                'key_bits': 4096,
                'max_path_length': -1,
                'exclude_cn_from_sans': False,
            }

            response = secrets_manager_service.create_configuration(
                configuration_prototype=configuration_prototype_model,
            )
            configuration = response.get_result()

            print(json.dumps(configuration, indent=2))

            # end-create_configuration

            configuration_name_for_get_configuration_link = configuration['name']
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secret_groups_example(self):
        """
        list_secret_groups request example
        """
        try:
            print('\nlist_secret_groups() result:')
            # begin-list_secret_groups

            response = secrets_manager_service.list_secret_groups()
            secret_group_collection = response.get_result()

            print(json.dumps(secret_group_collection, indent=2))

            # end-list_secret_groups

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_group_example(self):
        """
        get_secret_group request example
        """
        try:
            print('\nget_secret_group() result:')
            # begin-get_secret_group

            response = secrets_manager_service.get_secret_group(
                id=secret_group_id_for_get_secret_group_link,
            )
            secret_group = response.get_result()

            print(json.dumps(secret_group, indent=2))

            # end-get_secret_group

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_update_secret_group_example(self):
        """
        update_secret_group request example
        """
        try:
            print('\nupdate_secret_group() result:')
            # begin-update_secret_group

            secret_group_patch_model = {
            }

            response = secrets_manager_service.update_secret_group(
                id=secret_group_id_for_get_secret_group_link,
                secret_group_patch=secret_group_patch_model,
            )
            secret_group = response.get_result()

            print(json.dumps(secret_group, indent=2))

            # end-update_secret_group

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secrets_example(self):
        """
        list_secrets request example
        """
        try:
            print('\nlist_secrets() result:')
            # begin-list_secrets

            all_results = []
            pager = SecretsPager(
                client=secrets_manager_service,
                limit=10,
                sort='created_at',
                search='example',
                groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            )
            while pager.has_next():
                next_page = pager.get_next()
                assert next_page is not None
                all_results.extend(next_page)

            print(json.dumps(all_results, indent=2))

            # end-list_secrets
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_example(self):
        """
        get_secret request example
        """
        try:
            print('\nget_secret() result:')
            # begin-get_secret

            response = secrets_manager_service.get_secret(
                id=secret_id_for_get_secret_link,
            )
            secret = response.get_result()

            print(json.dumps(secret, indent=2))

            # end-get_secret

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_metadata_example(self):
        """
        get_secret_metadata request example
        """
        try:
            print('\nget_secret_metadata() result:')
            # begin-get_secret_metadata

            response = secrets_manager_service.get_secret_metadata(
                id=secret_id_for_get_secret_link,
            )
            secret_metadata = response.get_result()

            print(json.dumps(secret_metadata, indent=2))

            # end-get_secret_metadata

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_action_example(self):
        """
        create_secret_action request example
        """
        try:
            print('\ncreate_secret_action() result:')
            # begin-create_secret_action

            secret_action_prototype_model = {
                'action_type': 'private_cert_action_revoke_certificate',
            }

            response = secrets_manager_service.create_secret_action(
                id=secret_id_for_get_secret_link,
                secret_action_prototype=secret_action_prototype_model,
            )
            secret_action = response.get_result()

            print(json.dumps(secret_action, indent=2))

            # end-create_secret_action

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_by_name_type_example(self):
        """
        get_secret_by_name_type request example
        """
        try:
            print('\nget_secret_by_name_type() result:')
            # begin-get_secret_by_name_type

            response = secrets_manager_service.get_secret_by_name_type(
                secret_type='arbitrary',
                name=secret_name_link,
                secret_group_name='default',
            )
            secret = response.get_result()

            print(json.dumps(secret, indent=2))

            # end-get_secret_by_name_type

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_version_example(self):
        """
        create_secret_version request example
        """
        try:
            print('\ncreate_secret_version() result:')
            # begin-create_secret_version

            secret_version_prototype_model = {
                'payload': 'updated secret credentials',
                'custom_metadata': {'metadata_custom_key':'metadata_custom_value'},
                'version_custom_metadata': {'custom_version_key':'custom_version_value'},
            }

            response = secrets_manager_service.create_secret_version(
                secret_id=secret_id_for_get_secret_link,
                secret_version_prototype=secret_version_prototype_model,
            )
            secret_version = response.get_result()

            print(json.dumps(secret_version, indent=2))

            # end-create_secret_version

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_version_example(self):
        """
        get_secret_version request example
        """
        try:
            print('\nget_secret_version() result:')
            # begin-get_secret_version

            response = secrets_manager_service.get_secret_version(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
            )
            secret_version = response.get_result()

            print(json.dumps(secret_version, indent=2))

            # end-get_secret_version

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_secret_version_metadata_example(self):
        """
        get_secret_version_metadata request example
        """
        try:
            print('\nget_secret_version_metadata() result:')
            # begin-get_secret_version_metadata

            response = secrets_manager_service.get_secret_version_metadata(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
            )
            secret_version_metadata = response.get_result()

            print(json.dumps(secret_version_metadata, indent=2))

            # end-get_secret_version_metadata

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_update_secret_version_metadata_example(self):
        """
        update_secret_version_metadata request example
        """
        try:
            print('\nupdate_secret_version_metadata() result:')
            # begin-update_secret_version_metadata

            secret_version_metadata_patch_model = {
            }

            response = secrets_manager_service.update_secret_version_metadata(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
                secret_version_metadata_patch=secret_version_metadata_patch_model,
            )
            secret_version_metadata = response.get_result()

            print(json.dumps(secret_version_metadata, indent=2))

            # end-update_secret_version_metadata

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_version_action_example(self):
        """
        create_secret_version_action request example
        """
        try:
            print('\ncreate_secret_version_action() result:')
            # begin-create_secret_version_action

            secret_version_action_prototype_model = {
                'action_type': 'private_cert_action_revoke_certificate',
            }

            response = secrets_manager_service.create_secret_version_action(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
                secret_version_action_prototype=secret_version_action_prototype_model,
            )
            version_action = response.get_result()

            print(json.dumps(version_action, indent=2))

            # end-create_secret_version_action

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secrets_locks_example(self):
        """
        list_secrets_locks request example
        """
        try:
            print('\nlist_secrets_locks() result:')
            # begin-list_secrets_locks

            all_results = []
            pager = SecretsLocksPager(
                client=secrets_manager_service,
                limit=10,
                search='example',
                groups=['default', 'cac40995-c37a-4dcb-9506-472869077634'],
            )
            while pager.has_next():
                next_page = pager.get_next()
                assert next_page is not None
                all_results.extend(next_page)

            print(json.dumps(all_results, indent=2))

            # end-list_secrets_locks
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secret_locks_example(self):
        """
        list_secret_locks request example
        """
        try:
            print('\nlist_secret_locks() result:')
            # begin-list_secret_locks

            all_results = []
            pager = SecretLocksPager(
                client=secrets_manager_service,
                id=secret_id_for_get_secret_link,
                limit=10,
                sort='name',
                search='example',
            )
            while pager.has_next():
                next_page = pager.get_next()
                assert next_page is not None
                all_results.extend(next_page)

            print(json.dumps(all_results, indent=2))

            # end-list_secret_locks
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_secret_version_locks_bulk_example(self):
        """
        create_secret_version_locks_bulk request example
        """
        try:
            print('\ncreate_secret_version_locks_bulk() result:')
            # begin-create_secret_version_locks_bulk

            secret_lock_prototype_model = {
                'name': 'lock-example-1',
                'description': 'lock for consumer 1',
                'attributes': {'key':'value'},
            }

            response = secrets_manager_service.create_secret_version_locks_bulk(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
                locks=[secret_lock_prototype_model],
            )
            secret_locks = response.get_result()

            print(json.dumps(secret_locks, indent=2))

            # end-create_secret_version_locks_bulk

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_secret_version_locks_example(self):
        """
        list_secret_version_locks request example
        """
        try:
            print('\nlist_secret_version_locks() result:')
            # begin-list_secret_version_locks

            all_results = []
            pager = SecretVersionLocksPager(
                client=secrets_manager_service,
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

            print(json.dumps(all_results, indent=2))

            # end-list_secret_version_locks
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_list_configurations_example(self):
        """
        list_configurations request example
        """
        try:
            print('\nlist_configurations() result:')
            # begin-list_configurations

            all_results = []
            pager = ConfigurationsPager(
                client=secrets_manager_service,
                limit=10,
                sort='config_type',
                search='example',
            )
            while pager.has_next():
                next_page = pager.get_next()
                assert next_page is not None
                all_results.extend(next_page)

            print(json.dumps(all_results, indent=2))

            # end-list_configurations
        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_configuration_example(self):
        """
        get_configuration request example
        """
        try:
            print('\nget_configuration() result:')
            # begin-get_configuration

            response = secrets_manager_service.get_configuration(
                name=configuration_name_for_get_configuration_link,
                x_sm_accept_configuration_type='private_cert_configuration_root_ca',
            )
            configuration = response.get_result()

            print(json.dumps(configuration, indent=2))

            # end-get_configuration

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_update_configuration_example(self):
        """
        update_configuration request example
        """
        try:
            print('\nupdate_configuration() result:')
            # begin-update_configuration

            configuration_patch_model = {
                'api_key': 'RmnPBn6n1dzoo0v3kyznKEpg0WzdTpW9lW7FtKa017_u',
            }

            response = secrets_manager_service.update_configuration(
                name=configuration_name_for_get_configuration_link,
                configuration_patch=configuration_patch_model,
                x_sm_accept_configuration_type='private_cert_configuration_root_ca',
            )
            configuration = response.get_result()

            print(json.dumps(configuration, indent=2))

            # end-update_configuration

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_configuration_action_example(self):
        """
        create_configuration_action request example
        """
        try:
            print('\ncreate_configuration_action() result:')
            # begin-create_configuration_action

            configuration_action_prototype_model = {
                'action_type': 'private_cert_configuration_action_rotate_crl',
            }

            response = secrets_manager_service.create_configuration_action(
                name=configuration_name_for_get_configuration_link,
                config_action_prototype=configuration_action_prototype_model,
                x_sm_accept_configuration_type='private_cert_configuration_root_ca',
            )
            configuration_action = response.get_result()

            print(json.dumps(configuration_action, indent=2))

            # end-create_configuration_action

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_create_notifications_registration_example(self):
        """
        create_notifications_registration request example
        """
        try:
            print('\ncreate_notifications_registration() result:')
            # begin-create_notifications_registration

            response = secrets_manager_service.create_notifications_registration(
                event_notifications_instance_crn='crn:v1:bluemix:public:event-notifications:us-south:a/22018f3c34ff4ff193698d15ca316946:578ad1a4-2fd8-4e66-95d5-79a842ba91f8::',
                event_notifications_source_name='My Secrets Manager',
                event_notifications_source_description='Optional description of this source in an Event Notifications instance.',
            )
            notifications_registration = response.get_result()

            print(json.dumps(notifications_registration, indent=2))

            # end-create_notifications_registration

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_notifications_registration_example(self):
        """
        get_notifications_registration request example
        """
        try:
            print('\nget_notifications_registration() result:')
            # begin-get_notifications_registration

            response = secrets_manager_service.get_notifications_registration()
            notifications_registration = response.get_result()

            print(json.dumps(notifications_registration, indent=2))

            # end-get_notifications_registration

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_get_notifications_registration_test_example(self):
        """
        get_notifications_registration_test request example
        """
        try:
            # begin-get_notifications_registration_test

            response = secrets_manager_service.get_notifications_registration_test()

            # end-get_notifications_registration_test
            print('\nget_notifications_registration_test() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_secret_group_example(self):
        """
        delete_secret_group request example
        """
        try:
            # begin-delete_secret_group

            response = secrets_manager_service.delete_secret_group(
                id=secret_group_id_for_get_secret_group_link,
            )

            # end-delete_secret_group
            print('\ndelete_secret_group() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_secret_version_data_example(self):
        """
        delete_secret_version_data request example
        """
        try:
            # begin-delete_secret_version_data

            response = secrets_manager_service.delete_secret_version_data(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
            )

            # end-delete_secret_version_data
            print('\ndelete_secret_version_data() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_secret_locks_bulk_example(self):
        """
        delete_secret_locks_bulk request example
        """
        try:
            print('\ndelete_secret_locks_bulk() result:')
            # begin-delete_secret_locks_bulk

            response = secrets_manager_service.delete_secret_locks_bulk(
                id=secret_id_for_get_secret_link,
                name=['lock-example-1'],
            )
            secret_locks = response.get_result()

            print(json.dumps(secret_locks, indent=2))

            # end-delete_secret_locks_bulk

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_secret_version_locks_bulk_example(self):
        """
        delete_secret_version_locks_bulk request example
        """
        try:
            print('\ndelete_secret_version_locks_bulk() result:')
            # begin-delete_secret_version_locks_bulk

            response = secrets_manager_service.delete_secret_version_locks_bulk(
                secret_id=secret_id_for_get_secret_link,
                id=secret_version_id_for_get_secret_version_link,
                name=['lock-example-1'],
            )
            secret_locks = response.get_result()

            print(json.dumps(secret_locks, indent=2))

            # end-delete_secret_version_locks_bulk

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_secret_example(self):
        """
        delete_secret request example
        """
        try:
            # begin-delete_secret

            response = secrets_manager_service.delete_secret(
                id=secret_id_for_get_secret_link,
            )

            # end-delete_secret
            print('\ndelete_secret() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_configuration_example(self):
        """
        delete_configuration request example
        """
        try:
            # begin-delete_configuration

            response = secrets_manager_service.delete_configuration(
                name=configuration_name_for_get_configuration_link,
                x_sm_accept_configuration_type='private_cert_configuration_root_ca',
            )

            # end-delete_configuration
            print('\ndelete_configuration() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))

    @needscredentials
    def test_delete_notifications_registration_example(self):
        """
        delete_notifications_registration request example
        """
        try:
            # begin-delete_notifications_registration

            response = secrets_manager_service.delete_notifications_registration()

            # end-delete_notifications_registration
            print('\ndelete_notifications_registration() response status code: ', response.get_status_code())

        except ApiException as e:
            pytest.fail(str(e))


# endregion
##############################################################################
# End of Examples for Service: SecretsManagerV2
##############################################################################
