import { CreateTokenWithIAMResponse } from '@aws-sdk/client-sso-oidc';
import { faker } from '@faker-js/faker';
import jwt from 'jsonwebtoken';

import { REFRESH_TOKEN_GRANT_URI } from '../src/constants';

export const generateAccountId = () => {
    return faker.string.fromCharacters('0123456789', 12);
};

export const generateRoleArn = () => {
    const accountId = generateAccountId();
    const roleName = faker.string.alpha(10);
    return `arn:aws:iam::${accountId}:role/${roleName}`;
};

export const generateApplicationId = () => {
    return `apl-${faker.string.alphanumeric(16)}`;
};

export const generateApplicationArn = (applicationId = generateApplicationId()) => {
    const accountId = generateAccountId();
    const instanceId = `ssoins-${faker.string.alphanumeric(16)}`;
    return `arn:aws:sso::${accountId}:application/${instanceId}/${applicationId}`;
};

export const generateIdentityToken = () => {
    return faker.string.alphanumeric(50);
};

type LowercaseSdkCredentials = { accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: Date };
type UppercaseSdkCredentials = { AccessKeyId: string; SecretAccessKey: string; SessionToken: string; Expiration: Date };

export function generateSdkCredentials(format: 'lowercase'): LowercaseSdkCredentials;
export function generateSdkCredentials(format: 'uppercase'): UppercaseSdkCredentials;
export function generateSdkCredentials(format: 'lowercase' | 'uppercase') {
    const credentials: UppercaseSdkCredentials = {
        AccessKeyId: faker.string.alphanumeric(24),
        SecretAccessKey: faker.string.alphanumeric(24),
        SessionToken: faker.string.alphanumeric(24),
        Expiration: new Date(),
    };
    if (format === 'uppercase') {
        return credentials;
    }
    return lowercaseSdkCredential(credentials);
}

export const lowercaseSdkCredential = (credentials: UppercaseSdkCredentials): LowercaseSdkCredentials => {
    return {
        accessKeyId: credentials.AccessKeyId,
        secretAccessKey: credentials.SecretAccessKey,
        sessionToken: credentials.SessionToken,
        expiration: credentials.Expiration,
    };
};

export const generateOidcTokens = (identityContext?: string): CreateTokenWithIAMResponse => {
    const now = new Date().getTime();
    return {
        accessToken: faker.string.alphanumeric(24),
        expiresIn: 3600,
        idToken: jwt.sign(
            {
                'sts:identity_context': identityContext || faker.string.alphanumeric(100),
                sub: faker.string.uuid(),
                iss: faker.internet.url(),
                exp: new Date(now + 60 * 1000).getTime(), // expire in 60 seconds
                iat: now,
            },
            faker.string.alphanumeric(24)
        ),
        issuedTokenType: REFRESH_TOKEN_GRANT_URI,
        refreshToken: faker.string.alphanumeric(24),
        scope: ['sts:identity_context', 'openid', 'aws'],
        tokenType: 'Bearer',
    };
};
