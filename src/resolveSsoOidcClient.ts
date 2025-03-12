import { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { AssumeRoleWithWebIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import type { CredentialProviderOptions } from '@aws-sdk/types';
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
