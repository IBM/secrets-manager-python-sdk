# IBM Cloud Secrets Manager Python SDK

A Python client library to interact with the [IBM Cloud® Secrets Manager APIs](https://cloud.ibm.com/apidocs/secrets-manager).

<details>
<summary>Table of Contents</summary>

* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
* [Authentication](#authentication)
* [Using the SDK](#using-the-sdk)
* [Questions](#questions)
* [Issues](#issues)
* [Contributing](#contributing)
* [License](#license)

</details>

## Overview

The IBM Cloud Secrets Manager Python SDK allows developers to programmatically interact with the following IBM Cloud
services:

| Service name                                                     | Imported class name  |
|------------------------------------------------------------------|----------------------|
| [Secrets Manager](https://cloud.ibm.com/apidocs/secrets-manager) | SecretsManagerV2     |

## Prerequisites

- An [IBM Cloud account](https://cloud.ibm.com/registration).
- A [Secrets Manager service instance](https://cloud.ibm.com/catalog/services/secrets-manager).
- An [IBM Cloud API key](https://cloud.ibm.com/iam/apikeys) that allows the SDK to access your account.
- Python 3.9 or above.

## Installation

To install, use `pip` or `easy_install`:

```bash
pip install --upgrade "ibm-secrets-manager-sdk"
```

or

```bash
easy_install --upgrade "ibm-secrets-manager-sdk"
```

## Authentication

Secrets Manager uses token-based Identity and Access Management (IAM) authentication.

With IAM authentication, you supply an API key that is used to generate an access token. Then, the access token is
included in each API request to Secrets Manager. Access tokens are valid for a limited amount of time and must be
regenerated.

Authentication for this SDK is accomplished by
using [IAM authenticators](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md#authentication). Import
authenticators from `ibm_cloud_sdk_core.authenticators`.

### Examples

#### Programmatic credentials

```python
from ibm_cloud_sdk_core.authenticators.iam_authenticator import IAMAuthenticator

secretsManager = SecretsManagerV2(
    authenticator=IAMAuthenticator(apikey='<IBM_CLOUD_API_KEY>')
)
```

To learn more about IAM authenticators and how to use them in your Python application, see
the [IBM Python SDK Core documentation](https://github.com/IBM/python-sdk-core/blob/master/Authentication.md).

## Using the SDK

### Basic usage

- Use the `set_service_url` method to set the endpoint URL that is specific to your Secrets Manager service instance. To
  find your endpoint URL, you can copy it from the **Endpoints** page in the Secrets Manager UI.

#### Examples

Construct a service client and use it to create and retrieve a secret from your Secrets Manager instance.

Here's an example `secrets_manager.py` file:

```python
from ibm_cloud_sdk_core.authenticators.iam_authenticator import IAMAuthenticator
from ibm_secrets_manager_sdk.secrets_manager_v2 import *

secretsManager = SecretsManagerV2(
    authenticator=IAMAuthenticator(apikey='<IBM_CLOUD_API_KEY>')
)

secretsManager.set_service_url('<SERVICE_URL>')

# create arbitrary secret
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

response = secretsManager.create_secret(
  secret_prototype=secret_prototype_model,
)

secretId = response.result['id']

# get arbitrary secret
response = secretsManager.get_secret(
    id=secretId
)

secretPayload = response.result['payload']
print('The arbitrary secret payload is: ' + secretPayload)

```

Replace the `apikey` and `set_service_url()` values. Then use the `python secrets_manager.py` command to run your
application. You should see the payload of the arbitrary secret that was created.

For more information and IBM Cloud SDK usage examples for Python, see
the [IBM Cloud SDK Common documentation](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md).

## Questions

If you're having difficulties using this SDK, you can ask questions about this project by
using [Stack Overflow](https://stackoverflow.com/questions/tagged/ibm-cloud+secrets-manager). Be sure to include
the `ibm-cloud` and `ibm-secrets-manager` tags.

You can also check out the [Secrets Manager documentation](https://cloud.ibm.com/docs/secrets-manager)
and [API reference](https://cloud.ibm.com/apidocs/secrets-manager) for more information about the service.

## Issues

If you encounter an issue with the project, you're welcome to submit
a [bug report](https://github.com/IBM/secrets-manager-python-sdk/issues) to help us improve.

## Contributing

For general contribution guidelines, see [CONTRIBUTING](CONTRIBUTING.md).

## License

This SDK project is released under the Apache 2.0 license. The license's full text can be found in [LICENSE](LICENSE).
