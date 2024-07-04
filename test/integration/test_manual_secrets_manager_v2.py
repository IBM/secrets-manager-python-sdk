import os
import pytest
from ibm_cloud_sdk_core import *
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

# Config file name
config_file = 'secrets_manager_v2.env'
rootCaName = "root-CA"
interCaName = "inter-CA"
templateName = "template-1"
rootConfigType = "private_cert_configuration_root_ca"
interConfigType = "private_cert_configuration_intermediate_ca"
templateConfigType = "private_cert_configuration_template"
iamConfigType = "iam_credentials_configuration"
iamConfigName = "iam-configuration"


def config_private_cert_engine(secrets_manager_service):
    # Create Root CA
    root_configuration_prototype_model = {
        'config_type': rootConfigType,
        'name': rootCaName,
        'max_ttl': '43830h',
        'common_name': 'localhost'
    }
    try:
        response = secrets_manager_service.create_configuration(
            configuration_prototype=root_configuration_prototype_model,

        )
        assert response.get_status_code() == 201
        configuration = response.get_result()
        assert configuration is not None

    except ApiException as err:
        if "already exists" not in err.message:
            raise AssertionError("Failed to create root_configuration")

    # Create Intermediate CA
    inter_configuration_prototype_model = {
        'config_type': interConfigType,
        'name': interCaName,
        'max_ttl': '43830h',
        'common_name': 'localhost',
        'issuer': rootCaName,
        'signing_method': 'internal'
    }
    try:
        response = secrets_manager_service.create_configuration(
            configuration_prototype=inter_configuration_prototype_model,
        )
        assert response.get_status_code() == 201
        configuration = response.get_result()
        assert configuration is not None

    except ApiException as err:
        if "already exists" not in err.message:
            raise AssertionError("Failed to create inter_configuration")

    # Sign Intermediate
    configuration_action_prototype_model = {
        'action_type': 'private_cert_configuration_action_sign_intermediate',
        'intermediate_certificate_authority': interCaName
    }

    response = secrets_manager_service.create_configuration_action(
        name=rootCaName,
        config_action_prototype=configuration_action_prototype_model,
        x_sm_accept_configuration_type=rootConfigType,
    )

    assert response.get_status_code() == 201
    configuration_action = response.get_result()
    assert configuration_action is not None

    # Create Template
    template_configuration_prototype_model = {
        'config_type': templateConfigType,
        'name': templateName,
        'certificate_authority': interCaName
    }
    try:
        response = secrets_manager_service.create_configuration(
            configuration_prototype=template_configuration_prototype_model,
        )
        assert response.get_status_code() == 201
        configuration = response.get_result()
        assert configuration is not None

    except ApiException as err:
        if "already exists" not in err.message:
            raise AssertionError("Failed to create template_configuration")


def create_private_certificate(secrets_manager_service, secret_name):
    secret_prototype_model = {
        'secret_type': 'private_cert',
        'name': secret_name,
        'certificate_template': templateName,
        'common_name': 'localhost',
        'ttl': '10h',
    }

    response = secrets_manager_service.create_secret(
        secret_prototype=secret_prototype_model,
    )

    assert response.get_status_code() == 201
    secret = response.get_result()
    assert secret is not None

    return secret['id']


def config_iam_credentials_engine(secrets_manager_service, apikey, access_group):
    # IAM Credentials Configuration setup
    configuration_prototype_model = {
        'config_type': iamConfigType,
        'name': iamConfigName,
        'api_key': apikey
    }

    try:
        response = secrets_manager_service.create_configuration(
            configuration_prototype=configuration_prototype_model,
        )
        assert response.get_status_code() == 201
        configuration = response.get_result()
        assert configuration is not None
    except ApiException as err:
        if "reached the maximum" not in err.message:
            raise AssertionError("Failed to create iam_config")

    # Create IAM Secret
    secret_prototype_model = {
        'secret_type': 'iam_credentials',
        'name': "iam-credentials-secret",
        'description': "iam-secret-test",
        'access_groups': [access_group],
        'ttl': '5m',
        'reuse_api_key': False,
    }

    response = secrets_manager_service.create_secret(
        secret_prototype=secret_prototype_model,
    )

    assert response.get_status_code() == 201
    secret = response.get_result()
    assert secret is not None
    iam_secret_id = secret['id']

    # get secret - generate credentials
    response = secrets_manager_service.get_secret(
        id=iam_secret_id,
    )

    assert response.get_status_code() == 200
    secret = response.get_result()
    assert secret is not None

    return iam_secret_id


def delete_secret(secrets_manager_service, secret_id):
    response = secrets_manager_service.delete_secret(
        id=secret_id,
    )
    assert response.get_status_code() == 204


def delete_configuration(secrets_manager_service, config_name, config_type):
    response = secrets_manager_service.delete_configuration(
        name=config_name,
        x_sm_accept_configuration_type=config_type,
    )

    assert response.get_status_code() == 204


class TestSecretsManagerV2Manual():
    config = None
    secrets_manager_service = None

    @classmethod
    def setup_class(cls):
        if os.path.exists(config_file):
            os.environ['IBM_CREDENTIALS_FILE'] = config_file

            cls.secrets_manager_service = SecretsManagerV2.new_instance(
            )
            assert cls.secrets_manager_service is not None

            cls.config = read_external_sources(
                SecretsManagerV2.DEFAULT_SERVICE_NAME)
            assert cls.config is not None
            cls.secrets_manager_service.enable_retries()

            # Private Cert engine tests setup
            config_private_cert_engine(cls.secrets_manager_service)
            cls.privateCertSecretId1 = create_private_certificate(cls.secrets_manager_service, "private-cert-secret1")
            cls.privateCertSecretId2 = create_private_certificate(cls.secrets_manager_service, "private-cert-secret2")

            # IAM Credentials tests setup
            cls.iamSecretId = config_iam_credentials_engine(cls.secrets_manager_service, cls.config['APIKEY'],
                                                            cls.config['ACCESS_GROUP'])

        print('Setup complete.')

    @pytest.fixture(autouse=True, scope='session')
    def setup_teardown(self):
        yield
        delete_secret(self.secrets_manager_service, self.privateCertSecretId1)
        delete_secret(self.secrets_manager_service, self.privateCertSecretId2)
        delete_secret(self.secrets_manager_service, self.iamSecretId)

        delete_configuration(self.secrets_manager_service, templateName, templateConfigType)
        delete_configuration(self.secrets_manager_service, interCaName, interConfigType)
        delete_configuration(self.secrets_manager_service, rootCaName, rootConfigType)
        delete_configuration(self.secrets_manager_service, iamConfigName, iamConfigType)
        print('TearDown complete.')

    needscredentials = pytest.mark.skipif(
        not os.path.exists(config_file), reason="External configuration not available, skipping..."
    )

    @needscredentials
    def test_delete_secret_version_data(self):
        response = self.secrets_manager_service.delete_secret_version_data(
            secret_id=self.iamSecretId,
            id="current",
        )

        assert response.get_status_code() == 204

    @needscredentials
    def test_create_secret_action(self):
        secret_action_prototype_model = {
            'action_type': 'private_cert_action_revoke_certificate',
        }

        response = self.secrets_manager_service.create_secret_action(
            id=self.privateCertSecretId1,
            secret_action_prototype=secret_action_prototype_model,
        )

        assert response.get_status_code() == 201
        secret_action = response.get_result()
        assert secret_action is not None

    @needscredentials
    def test_create_secret_version_action(self):
        secret_action_prototype_model = {
            'action_type': 'private_cert_action_revoke_certificate',
        }

        response = self.secrets_manager_service.create_secret_version_action(
            secret_id=self.privateCertSecretId2,
            id="current",
            secret_version_action_prototype=secret_action_prototype_model,
        )

        assert response.get_status_code() == 201
        secret_action = response.get_result()
        assert secret_action is not None

    @needscredentials
    def test_create_configuration_action(self):
        configuration_action_prototype_model = {
            'action_type': 'private_cert_configuration_action_rotate_crl',
        }

        response = self.secrets_manager_service.create_configuration_action(
            name=rootCaName,
            config_action_prototype=configuration_action_prototype_model,
            x_sm_accept_configuration_type='private_cert_configuration_root_ca',
        )

        assert response.get_status_code() == 201
        configuration_action = response.get_result()
        assert configuration_action is not None
