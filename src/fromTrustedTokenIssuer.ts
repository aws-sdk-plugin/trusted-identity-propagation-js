import type { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { STSClient } from '@aws-sdk/client-sts';
import { AssumeRoleCommand } from '@aws-sdk/client-sts';
import type { CredentialProviderOptions, RuntimeConfigAwsCredentialIdentityProvider } from '@aws-sdk/types';
import { CredentialsProviderError } from '@smithy/property-provider';
import { type JwtPayload, jwtDecode } from 'jwt-decode';

import { IDC_CONTEXT_PROVIDER_ARN, PACKAGE_NAME } from './constants';
import { getIdentityEnhancedSessionName } from './helpers';
import { resolveSsoOidcClient } from './resolveSsoOidcClient';
import { retrieveSsoOidcTokens } from './retrieveSsoOidcTokens';

export interface FromTrustedTokenIssuerProps extends CredentialProviderOptions {
    /**
     * A function that the customer implements which obtains an JSON web token
     * from their external identity provider.
     */
    webTokenProvider: () => Promise<string>;

    /**
     * An IAM role ARN which will be assumed with `AssumeRoleWithWebIdentity`
     * so that the OIDC and STS clients can be bootstrapped without a default
     * credentials provider.
     *
     * This field is optional. If this is not provided, the value of the
     * `accessRoleArn` parameter will be used.
     */
    applicationRoleArn?: string;

    /**
     * An IAM role ARN which will be assumed by the plugin with the user's
     * identity context.
     */
    accessRoleArn: string;

    /**
     * The unique identifier string for the client or application. This value
     * is an application ARN that has OAuth grants configured.
     */
    applicationArn: string;

    /**
     * Custom OIDC client with customer-defined configurations. If not
     * provided, an OIDC client using default configurations will be
     * instantiated and used.
     */
    ssoOidcClient?: SSOOIDCClient;

    /**
     * Custom STS client with customer-defined configurations, used to assume
     * `accessRoleArn` with the user's identity context. If not provided, an
     * STS client usin default configurations will be instantiated and used.
     */
    stsClient?: STSClient;

    /**
     * A function that returns the region used to initialize the parent SDK
     * client, and will be used to initialize other SDK clients. This will be
     * passed automatically from the parent SDK client configuration.
     */
    region?: () => Promise<string>;
}

export const fromTrustedTokenIssuer = (
    init: FromTrustedTokenIssuerProps
): RuntimeConfigAwsCredentialIdentityProvider => {
    let ssoOidcRefreshToken: string | undefined = undefined;

    return async ({ callerClientConfig } = {}) => {
        const logger = init.logger ?? callerClientConfig?.logger;
        logger?.debug(`${PACKAGE_NAME} - fromTrustedTokenIssuer`);

        const { webTokenProvider, applicationRoleArn, accessRoleArn, applicationArn } = init;
        if (!webTokenProvider || !accessRoleArn || !applicationArn) {
            throw new CredentialsProviderError(
                'Incomplete configuration. The fromTrustedTokenIssuer() argument hash must include ' +
                    '"webTokenProvider", "accessRoleArn", "applicationArn"',
                { logger, tryNextLink: false }
            );
        }

        const region = (await init.region?.()) ?? (await callerClientConfig?.region());
        if (!region) {
            throw new CredentialsProviderError('Region not found', { logger, tryNextLink: false });
        }

        let webToken: string | undefined = undefined;
        let ssoOidcClient = init.ssoOidcClient;

        if (!ssoOidcClient) {
            webToken = await webTokenProvider();
            ssoOidcClient = await resolveSsoOidcClient({
                webToken,
                applicationRoleArn: applicationRoleArn || accessRoleArn,
                applicationArn,
                region,
                logger,
            });
        }

        const idcTokens = await retrieveSsoOidcTokens({
            webTokenProvider: async () => webToken || webTokenProvider(),
            ssoOidcClient,
            ssoOidcRefreshToken,
            applicationArn,
        });
        if (!idcTokens.idToken) {
            throw new CredentialsProviderError('Identity token not found', { logger, tryNextLink: false });
        }

        ssoOidcRefreshToken = idcTokens.refreshToken;

        // TODO: To be removed. We are going to get `sts:identity_context` from the response of `CreateTokenWithIAM`.
        const parsedIdcTokens = jwtDecode<JwtPayload & { 'sts:identity_context': string }>(idcTokens.idToken);

        const stsClient =
            init.stsClient ||
            new STSClient({
                credentials: ssoOidcClient.config.credentials,
                region,
                logger,
            });

        const { Credentials: tipTokens } = await stsClient.send(
            new AssumeRoleCommand({
                RoleArn: accessRoleArn,
                RoleSessionName: getIdentityEnhancedSessionName(applicationArn),
                ProvidedContexts: [
                    {
                        ProviderArn: IDC_CONTEXT_PROVIDER_ARN,
                        ContextAssertion: parsedIdcTokens['sts:identity_context'],
                    },
                ],
            })
        );

        if (!tipTokens?.AccessKeyId || !tipTokens.SecretAccessKey || !tipTokens.SessionToken) {
            throw new CredentialsProviderError('Failed to get credentials using AssumeRole', {
                logger,
                tryNextLink: false,
            });
        }

        return {
            accessKeyId: tipTokens.AccessKeyId,
            secretAccessKey: tipTokens.SecretAccessKey,
            sessionToken: tipTokens.SessionToken,
            expiration: tipTokens.Expiration,
        };
    };
};
