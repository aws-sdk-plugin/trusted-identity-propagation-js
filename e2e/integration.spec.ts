import { InvalidGrantException, SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { STSClient } from '@aws-sdk/client-sts';
import { describe, it } from 'vitest';
import {
    generateWebToken,
    getIntegrationTestEnvironment,
    getIntegrationTestPrivateKey,
    getInvalidPrivateKey,
} from '../tests/helpers';

import { TrustedIdentityPropagationExtension } from '../src/trustedIdentityPropagationExtension';

const env = getIntegrationTestEnvironment();
const ssoOidcClient = new SSOOIDCClient({ region: env.Region });

describe.concurrent('integration tests', () => {
    it('returns credentials when given a valid web token', async ({ expect }) => {
        const privateKey = getIntegrationTestPrivateKey();
        const testClient = new STSClient({
            region: env.Region,
            extensions: [
                TrustedIdentityPropagationExtension.create({
                    webTokenProvider: () => generateWebToken(env, privateKey),
                    applicationRoleArn: env.ApplicationRoleArn,
                    accessRoleArn: env.AccessRoleArn,
                    applicationArn: env.IdcApplicationArn,
                    ssoOidcClient,
                }),
            ],
        });

        const credentials = await testClient.config.credentials();

        expect(credentials.accessKeyId).toBeTypeOf('string');
        expect(credentials.secretAccessKey).toBeTypeOf('string');
        expect(credentials.sessionToken).toBeTypeOf('string');
        expect(credentials.expiration).toBeDefined();
        expect(credentials.expiration?.getTime()).toBeGreaterThan(new Date().getTime());
    });

    it('throws an error when given an invalid web token', async ({ expect }) => {
        const privateKey = getInvalidPrivateKey();
        const testClient = new STSClient({
            region: env.Region,
            extensions: [
                TrustedIdentityPropagationExtension.create({
                    webTokenProvider: () => generateWebToken(env, privateKey),
                    applicationRoleArn: env.ApplicationRoleArn,
                    accessRoleArn: env.AccessRoleArn,
                    applicationArn: env.IdcApplicationArn,
                    ssoOidcClient,
                }),
            ],
        });

        await expect(() => testClient.config.credentials()).rejects.toThrow(InvalidGrantException);
    });
});
