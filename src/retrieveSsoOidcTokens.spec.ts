import { CreateTokenWithIAMCommand, ExpiredTokenException, SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { faker } from '@faker-js/faker';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
    generateApplicationArn,
    generateIdentityToken,
    generateOidcTokens,
    generateSdkCredentials,
} from '../tests/helpers';
import { mockSsoOidcClientOutputs } from '../tests/mocks';
import { JWT_BEARER_GRANT_URI, REFRESH_TOKEN_GRANT } from './constants';
import { retrieveSsoOidcTokens } from './retrieveSsoOidcTokens';

vi.mock('@aws-sdk/client-sso-oidc', async (importOriginal) => ({
    ...(await importOriginal()),
    CreateTokenWithIAMCommand: vi.fn().mockName('CreateTokenWithIAMCommand'),
}));

const region = 'us-east-1';
const ssoOidcClient = new SSOOIDCClient({
    region,
    credentials: generateSdkCredentials('lowercase'),
});

const applicationArn = generateApplicationArn();
const webToken = generateIdentityToken();
const webTokenProvider = vi.fn().mockResolvedValue(webToken);
const identityContext = faker.string.alphanumeric(100);
const oidcTokens = generateOidcTokens(identityContext);

describe('retrieveSsoOidcTokens', () => {
    beforeEach(() => {
        vi.clearAllMocks();

        mockSsoOidcClientOutputs({
            CreateTokenWithIAMCommand: () => oidcTokens,
        });
    });

    it('performs refresh token grant flow if "ssoOidcRefreshToken" is provided', async () => {
        await retrieveSsoOidcTokens({
            webTokenProvider,
            ssoOidcClient,
            ssoOidcRefreshToken: oidcTokens.refreshToken,
            applicationArn,
        });

        expect(CreateTokenWithIAMCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                clientId: applicationArn,
                grantType: REFRESH_TOKEN_GRANT,
                refreshToken: oidcTokens.refreshToken,
            })
        );
    });

    it('performs JWT bearer grant flow if "ssoOidcRefreshToken" is undefined', async () => {
        await retrieveSsoOidcTokens({
            webTokenProvider,
            ssoOidcClient,
            applicationArn,
        });

        expect(CreateTokenWithIAMCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                clientId: applicationArn,
                grantType: JWT_BEARER_GRANT_URI,
                assertion: webToken,
            })
        );
    });

    it('performs refresh token grant flow then JWT bearer grant flow if "ssoOidcRefreshToken" is expired', async () => {
        let hasThrownError = false;
        vi.spyOn(SSOOIDCClient.prototype, 'send').mockImplementation(async () => {
            if (hasThrownError) {
                return oidcTokens;
            }
            hasThrownError = true;
            throw new ExpiredTokenException({
                $metadata: {},
                message: 'Token is expired',
            });
        });

        await retrieveSsoOidcTokens({
            webTokenProvider,
            ssoOidcClient,
            ssoOidcRefreshToken: oidcTokens.refreshToken,
            applicationArn,
        });

        expect(CreateTokenWithIAMCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                clientId: applicationArn,
                grantType: REFRESH_TOKEN_GRANT,
                refreshToken: oidcTokens.refreshToken,
            })
        );
        expect(CreateTokenWithIAMCommand).toHaveBeenCalledWith(
            expect.objectContaining({
                clientId: applicationArn,
                grantType: JWT_BEARER_GRANT_URI,
                assertion: webToken,
            })
        );
    });
});
