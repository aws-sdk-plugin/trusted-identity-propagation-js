## Trusted Identity Propagation Plugin for AWS SDK for JavaScript v3

Trusted identity propagation enables AWS services to grant permissions based on user attributes such as group associations, add context to an IAM role identifying the user requesting access to AWS resources, and propagate this context to other AWS services.

This plugin provides the functionality to exchange an Id token issued by a trusted token issuer for an IAM Identity Center token and pass it to AWS services (e.g., AWS S3, Amazon Q) that use it to make authorization decisions.

## Installation

In your project, add `@aws-sdk-extension/trusted-identity-propagation` to your dependencies.

```bash
npm install @aws-sdk-extension/trusted-identity-propagation
```

## Usage

Initialize the plugin and provide it as an extension to the SDK that you want to use trusted identity propagation with.

```js
import { SSOAdminClient } from '@aws-sdk/client-sso-admin';
import { TrustedIdentityPropagationExtension } from '@aws-sdk-extension/trusted-identity-propagation';

// Plugin configurations, please refer to the documentation on each of these fields.
const applicationRoleArn = 'YOUR_APPLICATION_ROLE_ARN';
const accessRoleArn = 'YOUR_ACCESS_ROLE_ARN';
const applicationArn = 'YOUR_APPLICATION_ARN';

const ssoAdminClient = new SSOAdminClient({
    region: 'us-east-1',
    extensions: [
        TrustedIdentityPropagationExtension.create({
            webTokenProvider: async () => {
                return 'ID_TOKEN_FROM_YOUR_IDENTITY_PROVIDER';
            },
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        }),
    ],
});
```

## Install from source

The plugin has been published to NPM and can be installed as described above. If you want to play with the latest version, you can build from source as follows.

1. Clone this repository locally
```bash
git clone https://github.com/aws-sdk-plugin/trusted-identity-propagation-js.git
```

2. Install dependencies and build the plugin
```bash
npm ci
npm run build
```

3. Pack the plugin
```bash
npm pack
```

This will create an archive file named something like `aws-sdk-extension-trusted-identity-propagation-1.0.0.tgz`. The version number at the end changes based on the current version of the plugin.

4. Change directory to the project you are working on and move the archive file to the location to store the vendor packages
```bash
mv path/to/trusted-identity-propagation-js/aws-sdk-extension-trusted-identity-propagation-1.0.0.tgz ./path/to/vendors/folder
```

5. Install the package to your project
```bash
npm install ./path/to/vendors/folder/aws-sdk-extension-trusted-identity-propagation-1.0.0.tgz
```

## Node.js versions

This plugin supports Node.js >= 18.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
