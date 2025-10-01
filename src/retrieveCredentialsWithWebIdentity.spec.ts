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
import { retrieveCredentialsWithWebIdentity } from './retrieveCredentialsWithWebIdentity';

vi.mock('@aws-sdk/client-sts', async (importOriginal) => ({
    ...(await importOriginal()),
    AssumeRoleWithWebIdentityCommand: vi.fn().mockName('AssumeRoleWithWebIdentityCommand'),
}));

const webToken = generateIdentityToken();
const applicationRoleArn = generateRoleArn();
const applicationArn = generateApplicationArn();
const region = 'us-east-1';

describe('retrieveCredentialsWithWebIdentity', () => {
    const bootstrapSdkCredentials = generateSdkCredentials('uppercase');
    const credentials = lowercaseSdkCredential(bootstrapSdkCredentials);

    beforeEach(() => {
        vi.clearAllMocks();

        mockStsClientOutputs({
            AssumeRoleWithWebIdentityCommand: () => ({ Credentials: bootstrapSdkCredentials }),
        });
    });

    it('returns new session using the web identity token', async () => {
        const result = await retrieveCredentialsWithWebIdentity({
            webToken,
            applicationRoleArn,
            applicationArn,
            region,
        });

        expect(await result).toEqual(
            expect.objectContaining({
                accessKeyId: credentials.accessKeyId,
                secretAccessKey: credentials.secretAccessKey,
                sessionToken: credentials.sessionToken,
            })
        );
        expect(AssumeRoleWithWebIdentityCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                RoleArn: applicationRoleArn,
                RoleSessionName: expect.any(String),
                WebIdentityToken: webToken,
            })
        );
    });
});
