import { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { AssumeRoleWithWebIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import type { AwsCredentialIdentity, CredentialProviderOptions } from '@aws-sdk/types';
import { CredentialsProviderError } from '@smithy/property-provider';
import { getBootstrapSessionName } from './helpers';

export interface RetrieveCredentialsWithWebIdentityParameters {
    webToken: string;
    applicationRoleArn: string;
    applicationArn: string;
    region: string;
}

export const retrieveCredentialsWithWebIdentity = async ({
    webToken,
    applicationRoleArn,
    applicationArn,
    region,
    logger,
}: RetrieveCredentialsWithWebIdentityParameters & CredentialProviderOptions): Promise<AwsCredentialIdentity> => {
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

    const staticCredentials: AwsCredentialIdentity = {
      accessKeyId: iamTokens.AccessKeyId,
      secretAccessKey: iamTokens.SecretAccessKey,
      sessionToken: iamTokens.SessionToken,
    };

    return staticCredentials;
};
