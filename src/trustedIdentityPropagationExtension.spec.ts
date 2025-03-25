import { describe, expect, it, vi } from 'vitest';

import { generateApplicationArn, generateIdentityToken, generateRoleArn } from '../tests/helpers';
import { mockFromTrustedTokenIssuer } from '../tests/mocks';
import type { FromTrustedTokenIssuerProps } from './fromTrustedTokenIssuer';
import { TrustedIdentityPropagationExtension } from './trustedIdentityPropagationExtension';

const region = 'us-east-1';
const webToken = generateIdentityToken();
const webTokenProvider = vi.fn().mockResolvedValue(webToken);
const applicationRoleArn = generateRoleArn();
const accessRoleArn = generateRoleArn();
const applicationArn = generateApplicationArn();

const configuration: FromTrustedTokenIssuerProps = {
    webTokenProvider,
    applicationRoleArn,
    accessRoleArn,
    applicationArn,
};
const extensionConfiguration = {
    credentials: vi.fn(),
    setCredentials: vi.fn(),
    region: vi.fn().mockResolvedValue(region),
};

describe('TrustedIdentityPropagationExtension', () => {
    describe('create()', () => {
        it('returns a new instance of the extension', () => {
            const extension = TrustedIdentityPropagationExtension.create(configuration);

            expect(extension).toBeInstanceOf(TrustedIdentityPropagationExtension);
        });
    });

    describe('configure()', () => {
        it('calls the fromTrustedTokenIssuer credentials provider', () => {
            const credentialProviderFn = vi.fn();
            const fromTrustedTokenIssuer = mockFromTrustedTokenIssuer(credentialProviderFn);

            const extension = TrustedIdentityPropagationExtension.create(configuration);
            extension.configure(extensionConfiguration);

            expect(fromTrustedTokenIssuer).toHaveBeenCalledWith(expect.objectContaining(configuration));
            expect(extensionConfiguration.setCredentials).toHaveBeenCalledWith(credentialProviderFn);
        });
    });
});
