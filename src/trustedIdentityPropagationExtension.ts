import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from '@aws-sdk/types';
import { type FromTrustedTokenIssuerProps, fromTrustedTokenIssuer } from './fromTrustedTokenIssuer';

interface ExtensionConfiguration {
    credentials(): AwsCredentialIdentity | AwsCredentialIdentityProvider | undefined;
    setCredentials(credentials: AwsCredentialIdentity | AwsCredentialIdentityProvider): void;
    region(): () => Promise<string>;
}

export class TrustedIdentityPropagationExtension {
    private readonly configuration: FromTrustedTokenIssuerProps;

    private constructor(configuration: FromTrustedTokenIssuerProps) {
        this.configuration = configuration;
    }

    static create(configuration: FromTrustedTokenIssuerProps) {
        return new TrustedIdentityPropagationExtension(configuration);
    }

    configure(extensionConfiguration: ExtensionConfiguration) {
        extensionConfiguration.setCredentials(fromTrustedTokenIssuer(this.configuration));
    }
}
