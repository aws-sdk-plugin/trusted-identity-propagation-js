import pkg from '../package.json';

export const JWT_BEARER_GRANT_URI = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
export const REFRESH_TOKEN_TYPE_URI = 'urn:ietf:params:oauth:token-type:refresh_token';
export const REFRESH_TOKEN_GRANT = 'refresh_token';

export const IDC_CONTEXT_PROVIDER_ARN = 'arn:aws:iam::aws:contextProvider/IdentityCenter';

export const PACKAGE_NAME = pkg.name;
export const PACKAGE_VERSION = pkg.version;

export const PLUGIN_METRIC_PREFIX = 'p';
export const PLUGIN_METRIC_LABEL = 'aws-tip';
