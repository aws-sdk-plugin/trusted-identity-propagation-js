import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from '@aws-sdk/types';
import { type FromTrustedTokenIssuerProps, fromTrustedTokenIssuer } from './fromTrustedTokenIssuer';

interface ExtensionConfiguration {
    credentials(): AwsCredentialIdentity | AwsCredentialIdentityProvider | undefined;
    setCredentials(credentials: AwsCredentialIdentity | AwsCredentialIdentityProvider): void;
    region(): () => Promise<string>;
}

type ExtensionInitProps = Omit<FromTrustedTokenIssuerProps, 'region'>;

export class TrustedIdentityPropagationExtension {
    private readonly configuration: ExtensionInitProps;

    private constructor(configuration: ExtensionInitProps) {
        this.configuration = configuration;
    }

    static create(configuration: ExtensionInitProps) {
        return new TrustedIdentityPropagationExtension(configuration);
    }

    configure(extensionConfiguration: ExtensionConfiguration) {
        extensionConfiguration.setCredentials(
            fromTrustedTokenIssuer({
                ...this.configuration,
                region: extensionConfiguration.region(),
            })
        );
    }
}
