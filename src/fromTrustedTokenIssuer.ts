import type { SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import type { STSClient } from '@aws-sdk/client-sts';
import type { CredentialProviderOptions, RuntimeConfigAwsCredentialIdentityProvider } from '@aws-sdk/types';

export interface FromTrustedTokenIssuerProps extends CredentialProviderOptions {
    /**
     * A function that the customer implements which obtains an OpenID token
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
    return async () => {
        // @ts-expect-error
        console.log(init);

        // NOTE: Setting blank values for now until actual plugin implementation.
        return {
            accessKeyId: '',
            secretAccessKey: '',
            sessionToken: '',
            expiration: new Date(),
        };
    };
};
