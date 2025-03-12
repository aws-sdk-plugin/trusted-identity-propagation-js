import { AssumeRoleWithWebIdentityCommand } from '@aws-sdk/client-sts';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateApplicationArn,
    generateIdentityToken,
    generateRoleArn,
    generateSdkCredentials,
    lowercaseSdkCredential,
} from '../tests/helpers';
import { mockStsClientOutputs } from '../tests/mocks';
import { resolveSsoOidcClient } from './resolveSsoOidcClient';

vi.mock('@aws-sdk/client-sso-oidc', (importOriginal) => importOriginal());
vi.mock('@aws-sdk/client-sts', async (importOriginal) => ({
    ...(await importOriginal()),
    AssumeRoleWithWebIdentityCommand: vi.fn().mockName('AssumeRoleWithWebIdentityCommand'),
}));

const webToken = generateIdentityToken();
const applicationRoleArn = generateRoleArn();
const applicationArn = generateApplicationArn();
const region = 'us-east-1';

describe('resolveSsoOidcClient', () => {
    const bootstrapSdkCredentials = generateSdkCredentials('uppercase');
    const credentials = lowercaseSdkCredential(bootstrapSdkCredentials);

    beforeEach(() => {
        vi.clearAllMocks();

        mockStsClientOutputs({
            AssumeRoleWithWebIdentityCommand: () => ({ Credentials: bootstrapSdkCredentials }),
        });
    });

    it('returns new SSOOIDCClient using bootstrapped session', async () => {
        const result = await resolveSsoOidcClient({
            webToken,
            applicationRoleArn,
            applicationArn,
            region,
        });

        expect(await result.config.credentials()).toEqual(
            expect.objectContaining({
                accessKeyId: credentials.accessKeyId,
                secretAccessKey: credentials.secretAccessKey,
                sessionToken: credentials.sessionToken,
            })
        );
        expect(await result.config.region()).toEqual(region);
        expect(AssumeRoleWithWebIdentityCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                RoleArn: applicationRoleArn,
                RoleSessionName: expect.any(String),
                WebIdentityToken: webToken,
            })
        );
    });
});
