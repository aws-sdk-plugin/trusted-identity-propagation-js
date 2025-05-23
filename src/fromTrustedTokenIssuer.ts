import type { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { STSClient } from '@aws-sdk/client-sts';
import { AssumeRoleCommand } from '@aws-sdk/client-sts';
import type {
    CredentialProviderOptions,
    RuntimeConfigAwsCredentialIdentityProvider,
    UserAgentPair,
} from '@aws-sdk/types';
import { CredentialsProviderError } from '@smithy/property-provider';

import {
    IDC_CONTEXT_PROVIDER_ARN,
    PACKAGE_NAME,
    PACKAGE_VERSION,
    PLUGIN_METRIC_LABEL,
    PLUGIN_METRIC_PREFIX,
} from './constants';
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

        const region = await callerClientConfig?.region();
        if (!region) {
            throw new CredentialsProviderError('Region not found', { logger, tryNextLink: false });
        }

        const pluginUserAgentSegment: UserAgentPair = [
            PLUGIN_METRIC_PREFIX,
            `${PLUGIN_METRIC_LABEL}#${PACKAGE_VERSION}`,
        ];

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
        ssoOidcClient.config.customUserAgent ??= [];
        ssoOidcClient.config.customUserAgent.push(pluginUserAgentSegment);

        const idcTokens = await retrieveSsoOidcTokens({
            webTokenProvider: async () => webToken || webTokenProvider(),
            ssoOidcClient,
            ssoOidcRefreshToken,
            applicationArn,
        });
        if (!idcTokens.awsAdditionalDetails?.identityContext) {
            throw new CredentialsProviderError('Identity context not found', { logger, tryNextLink: false });
        }

        ssoOidcRefreshToken = idcTokens.refreshToken;

        const stsClient =
            init.stsClient ||
            new STSClient({
                credentials: ssoOidcClient.config.credentials,
                region,
                logger,
            });
        stsClient.config.customUserAgent ??= [];
        stsClient.config.customUserAgent.push(pluginUserAgentSegment);

        const { Credentials: tipTokens } = await stsClient.send(
            new AssumeRoleCommand({
                RoleArn: accessRoleArn,
                RoleSessionName: getIdentityEnhancedSessionName(applicationArn),
                ProvidedContexts: [
                    {
                        ProviderArn: IDC_CONTEXT_PROVIDER_ARN,
                        ContextAssertion: idcTokens.awsAdditionalDetails.identityContext,
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
