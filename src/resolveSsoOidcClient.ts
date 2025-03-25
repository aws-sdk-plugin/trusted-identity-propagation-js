import { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { AssumeRoleWithWebIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import type { CredentialProviderOptions } from '@aws-sdk/types';
import { CredentialsProviderError } from '@smithy/property-provider';
import { getBootstrapSessionName } from './helpers';

export interface ResolveSsoOidcClientParameters {
    webToken: string;
    applicationRoleArn: string;
    applicationArn: string;
    region: string;
}

export const resolveSsoOidcClient = async ({
    webToken,
    applicationRoleArn,
    applicationArn,
    region,
    logger,
}: ResolveSsoOidcClientParameters & CredentialProviderOptions): Promise<SSOOIDCClient> => {
    const stsClient = new STSClient({ region, logger });
    const { Credentials: iamTokens } = await stsClient.send(
        new AssumeRoleWithWebIdentityCommand({
            RoleArn: applicationRoleArn,
            RoleSessionName: getBootstrapSessionName(applicationArn),
            WebIdentityToken: webToken,
        })
    );

    if (!iamTokens?.AccessKeyId || !iamTokens.SecretAccessKey || !iamTokens.SessionToken) {
        throw new CredentialsProviderError('Failed to get credentials using AssumeRoleWithWebIdentity', {
            logger,
            tryNextLink: false,
        });
    }

    return new SSOOIDCClient({
        credentials: {
            accessKeyId: iamTokens.AccessKeyId,
            secretAccessKey: iamTokens.SecretAccessKey,
            sessionToken: iamTokens.SessionToken,
        },
        region,
        logger,
    });
};
