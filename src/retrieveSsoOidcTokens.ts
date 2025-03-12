import {
    CreateTokenWithIAMCommand,
    type CreateTokenWithIAMResponse,
    ExpiredTokenException,
    type SSOOIDCClient,
} from '@aws-sdk/client-sso-oidc';
import { JWT_BEARER_GRANT_URI, REFRESH_TOKEN_GRANT } from './constants';

export interface RetrieveSsoOidcTokensParameters {
    webTokenProvider: () => Promise<string>;
    ssoOidcClient: SSOOIDCClient;
    ssoOidcRefreshToken?: string;
    applicationArn: string;
}

export const retrieveSsoOidcTokens = async ({
    webTokenProvider,
    ssoOidcClient,
    ssoOidcRefreshToken,
    applicationArn,
}: RetrieveSsoOidcTokensParameters): Promise<CreateTokenWithIAMResponse> => {
    let refreshTokenExpired = false;
    let idcTokens: CreateTokenWithIAMResponse;

    if (ssoOidcRefreshToken) {
        try {
            idcTokens = await ssoOidcClient.send(
                new CreateTokenWithIAMCommand({
                    clientId: applicationArn,
                    grantType: REFRESH_TOKEN_GRANT,
                    refreshToken: ssoOidcRefreshToken,
                })
            );
        } catch (error) {
            if (error instanceof ExpiredTokenException) {
                refreshTokenExpired = true;
            } else {
                throw error;
            }
        }
    }

    if (!ssoOidcRefreshToken || refreshTokenExpired) {
        idcTokens = await ssoOidcClient.send(
            new CreateTokenWithIAMCommand({
                clientId: applicationArn,
                grantType: JWT_BEARER_GRANT_URI,
                assertion: await webTokenProvider(),
            })
        );
    }

    return idcTokens;
};
