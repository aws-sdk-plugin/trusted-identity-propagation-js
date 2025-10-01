import { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import type { AwsIdentityProperties } from '@aws-sdk/types';
import { faker } from '@faker-js/faker';
import { type MockInstance, beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateApplicationArn,
    generateIdentityToken,
    generateOidcTokens,
    generateRoleArn,
    generateSdkCredentials,
    lowercaseSdkCredential,
} from '../tests/helpers';
import {
    mockRetrieveCredentialsWithWebIdentity,
    mockRetrieveSsoOidcTokens,
    mockSsoOidcClientOutputs,
    mockStsClientOutputs,
} from '../tests/mocks';
import { IDC_CONTEXT_PROVIDER_ARN } from './constants';
import { type FromTrustedTokenIssuerProps, fromTrustedTokenIssuer } from './fromTrustedTokenIssuer';

vi.mock('@aws-sdk/client-sso-oidc', async (importOriginal) => ({
    ...(await importOriginal()),
    CreateTokenWithIAMCommand: vi.fn().mockName('CreateTokenWithIAMCommand'),
}));
vi.mock('@aws-sdk/client-sts', async (importOriginal) => ({
    ...(await importOriginal()),
    AssumeRoleCommand: vi.fn().mockName('AssumeRoleCommand'),
}));

const region = 'us-east-1';
const webToken = generateIdentityToken();
const webTokenProvider = vi.fn().mockResolvedValue(webToken);
const applicationRoleArn = generateRoleArn();
const accessRoleArn = generateRoleArn();
const applicationArn = generateApplicationArn();

const callerClientConfig: AwsIdentityProperties['callerClientConfig'] = {
    region: () => Promise.resolve(region),
};

const ssoOidcClient = new SSOOIDCClient({
    region,
    credentials: generateSdkCredentials('lowercase'),
});

const stsClient = new STSClient({
    region,
    credentials: generateSdkCredentials('lowercase'),
});

describe('fromTrustedTokenIssuer', () => {
    const bootstrapCredentials = generateSdkCredentials('uppercase');
    const identityContext = faker.string.alphanumeric(100);
    const oidcTokens = generateOidcTokens(identityContext);
    const identityEnhancedCredentials = generateSdkCredentials('uppercase');

    let retrieveCredentialsWithWebIdentity: MockInstance;

    beforeEach(() => {
        vi.clearAllMocks();

        retrieveCredentialsWithWebIdentity = mockRetrieveCredentialsWithWebIdentity();

        mockStsClientOutputs({
            AssumeRoleWithWebIdentityCommand: () => ({ Credentials: bootstrapCredentials }),
            AssumeRoleCommand: () => ({ Credentials: identityEnhancedCredentials }),
        });
        mockSsoOidcClientOutputs({
            CreateTokenWithIAMCommand: () => oidcTokens,
        });
    });

    ['webTokenProvider', 'accessRoleArn', 'applicationArn'].forEach((field) => {
        const config: FromTrustedTokenIssuerProps = {
            webTokenProvider,
            accessRoleArn,
            applicationArn,
        };

        it(`throws error if required field "${field}" is not provided`, async () => {
            const testConfig = { ...config };
            delete testConfig[field];

            await expect(() => fromTrustedTokenIssuer(testConfig)({ callerClientConfig })).rejects.toThrow(
                'Incomplete configuration. The fromTrustedTokenIssuer() argument hash must include "webTokenProvider", "accessRoleArn", "applicationArn"'
            );
        });
    });

    it('throws error if both applicationRoleArn, ssoOidcClient and ssoOidcClient is not provided', async () => {
        const config: FromTrustedTokenIssuerProps = {
            webTokenProvider,
            accessRoleArn,
            applicationArn,
            stsClient,
        };

        await expect(() => fromTrustedTokenIssuer(config)({ callerClientConfig })).rejects.toThrow(
            'Either both of ssoOidcClient and stsClient OR the application role must be provided.'
        );
    });

    it('throws error if both applicationRoleArn and ssoOidcClient is not provided', async () => {
        const config: FromTrustedTokenIssuerProps = {
            webTokenProvider,
            accessRoleArn,
            applicationArn,
            stsClient,
        };

        await expect(() => fromTrustedTokenIssuer(config)({ callerClientConfig })).rejects.toThrow(
            'Either both of ssoOidcClient and stsClient OR the application role must be provided.'
        );
    });

    it('throws error if both applicationRoleArn and stsClient is not provided', async () => {
        const config: FromTrustedTokenIssuerProps = {
            webTokenProvider,
            accessRoleArn,
            applicationArn,
            ssoOidcClient,
        };

        await expect(() => fromTrustedTokenIssuer(config)({ callerClientConfig })).rejects.toThrow(
            'Either both of ssoOidcClient and stsClient OR the application role must be provided.'
        );
    });

    it('throws error if both applicationRoleArn and accessRoleArn are same', async () => {
        const config: FromTrustedTokenIssuerProps = {
            webTokenProvider,
            applicationRoleArn: accessRoleArn,
            accessRoleArn,
            applicationArn,
        };

        await expect(() => fromTrustedTokenIssuer(config)({ callerClientConfig })).rejects.toThrow(
            'Access Role and Application Role can not be same as it leads to self role assumption.'
        );
    });

    it('uses region from callerClientConfig', async () => {
        await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        expect(retrieveCredentialsWithWebIdentity).toHaveBeenCalledWith(expect.objectContaining({ region }));
    });

    it('throws error if region cannot be determined', async () => {
        await expect(() =>
            fromTrustedTokenIssuer({
                webTokenProvider,
                applicationRoleArn,
                accessRoleArn,
                applicationArn,
            })()
        ).rejects.toThrow('Region not found');
    });

    it('calls "retrieveCredentialsWithWebIdentity" if "ssoOidcClient" is not provided', async () => {
        await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        expect(retrieveCredentialsWithWebIdentity).toHaveBeenCalledWith(
            expect.objectContaining({
                webToken,
                applicationRoleArn,
                applicationArn,
                region,
            })
        );
    });

    it('calls the "webTokenProvider" only once when custom "ssoOidcClient" is not provided', async () => {
        /**
         * When a custom `ssoOidcClient` is not provided, the external IDP tokens are used twice:
         *   1. Passed to `AssumeRoleWithWebIdentity` to bootstrap the SSO OIDC client
         *   2. Passed to `CreateTokenWithIAM` to get the OIDC tokens
         * We should only call `webTokenProvider` once in this flow to reduce the number of potential API calls needed.
         *
         * Note that this does not cache the identity token for long running jobs that need to refresh the credentials.
         * `webTokenProvider` will be called again when our credential provider needs to refresh the credentials.
         */

        await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        expect(webTokenProvider).toHaveBeenCalledOnce();
    });

    it('calls the "webTokenProvider" only once when custom "ssoOidcClient" is provided', async () => {
        await fromTrustedTokenIssuer({
            webTokenProvider,
            accessRoleArn,
            applicationArn,
            ssoOidcClient,
            stsClient,
        })({ callerClientConfig });

        expect(webTokenProvider).toHaveBeenCalledOnce();
    });

    it('calls the "webTokenProvider" only once when custom "ssoOidcClient" is provided and credentials are refreshed', async () => {
        const provider = fromTrustedTokenIssuer({
            webTokenProvider,
            accessRoleArn,
            applicationArn,
            ssoOidcClient,
            stsClient,
        });

        /**
         * First call performs JWT bearer grant and caches the refresh token, then succeeding calls use the cached
         * refresh token to perform the refresh token grant flow.
         */
        await provider({ callerClientConfig });
        await provider({ callerClientConfig });

        /**
         * During the refresh token grant flow, the identity tokens from the external IDP are no longer used so it
         * should not call `webTokenProvider` again.
         */
        expect(webTokenProvider).toHaveBeenCalledOnce();
    });

    it('calls "retrieveSsoOidcTokens" with the "applicationArn" parameter and the user web token', async () => {
        const retrieveSsoOidcTokens = mockRetrieveSsoOidcTokens(oidcTokens);

        await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        const token = await retrieveSsoOidcTokens.mock.calls[0][0].webTokenProvider();

        expect(token).toEqual(webToken);
        expect(retrieveSsoOidcTokens).toHaveBeenCalledWith(
            expect.objectContaining({
                ssoOidcRefreshToken: undefined,
                applicationArn,
            })
        );
    });

    it('calls "retrieveSsoOidcTokens" with the refresh token if one was stored from previous requests', async () => {
        const retrieveSsoOidcTokens = mockRetrieveSsoOidcTokens(oidcTokens);

        const provider = fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        });

        /**
         * First call performs JWT bearer grant and caches the refresh token, then succeeding calls use the cached
         * refresh token to perform the refresh token grant flow.
         */
        await provider({ callerClientConfig });
        await provider({ callerClientConfig });

        expect(retrieveSsoOidcTokens).toHaveBeenCalledWith(
            expect.objectContaining({
                ssoOidcRefreshToken: undefined,
                applicationArn,
            })
        );
        expect(retrieveSsoOidcTokens).toHaveBeenCalledWith(
            expect.objectContaining({
                ssoOidcRefreshToken: oidcTokens.refreshToken,
                applicationArn,
            })
        );
    });

    it('calls "AssumeRole" with the "accessRoleArn" parameter and the user identity context assertion', async () => {
        await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        expect(AssumeRoleCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                RoleArn: accessRoleArn,
                RoleSessionName: expect.any(String),
                ProvidedContexts: [
                    {
                        ProviderArn: IDC_CONTEXT_PROVIDER_ARN,
                        ContextAssertion: identityContext,
                    },
                ],
            })
        );
    });

    it('returns identity-enhanced session with expiration from the "AssumeRole" response', async () => {
        const credentials = await fromTrustedTokenIssuer({
            webTokenProvider,
            applicationRoleArn,
            accessRoleArn,
            applicationArn,
        })({ callerClientConfig });

        expect(credentials).toEqual(lowercaseSdkCredential(identityEnhancedCredentials));
    });
});
