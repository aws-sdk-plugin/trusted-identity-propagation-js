import { CreateTokenWithIAMCommandOutput, CreateTokenWithIAMResponse, SSOOIDCClient } from '@aws-sdk/client-sso-oidc';
import { AssumeRoleCommandOutput, AssumeRoleWithWebIdentityCommandOutput, STSClient } from '@aws-sdk/client-sts';
import { vi } from 'vitest';

import * as resolveSsoOidcClient from '../src/resolveSsoOidcClient';
import * as retrieveSsoOidcTokens from '../src/retrieveSsoOidcTokens';

const testRegion = 'us-east-1';

export const mockResolveSsoOidcClient = () => {
    return vi
        .spyOn(resolveSsoOidcClient, 'resolveSsoOidcClient')
        .mockResolvedValue(new SSOOIDCClient({ region: testRegion }));
};

export const mockRetrieveSsoOidcTokens = (tokens: CreateTokenWithIAMResponse) => {
    return vi.spyOn(retrieveSsoOidcTokens, 'retrieveSsoOidcTokens').mockResolvedValue(tokens);
};

type MockedStsCommandOutputsMap = {
    AssumeRoleWithWebIdentityCommand: AssumeRoleWithWebIdentityCommandOutput;
    AssumeRoleCommand: AssumeRoleCommandOutput;
};
type MockedStsCommandOutputs = {
    [Command in keyof MockedStsCommandOutputsMap]?: () => Omit<MockedStsCommandOutputsMap[Command], '$metadata'>;
};

export const mockStsClientOutputs = (overrides: MockedStsCommandOutputs = {}) => {
    return vi.spyOn(STSClient.prototype, 'send').mockImplementation(async (command) => {
        const commandName =
            typeof command.constructor.getMockName === 'function'
                ? command.constructor.getMockName()
                : command.constructor.name;
        if (typeof overrides[commandName] !== 'function') {
            throw new Error(`Unknown command: ${commandName}`);
        }
        return overrides[commandName]();
    });
};

type MockedSsoOidcCommandOutputsMap = {
    CreateTokenWithIAMCommand: CreateTokenWithIAMCommandOutput;
};
type MockedSsoOidcCommandOutputs = {
    [Command in keyof MockedSsoOidcCommandOutputsMap]?: () => Omit<
        MockedSsoOidcCommandOutputsMap[Command],
        '$metadata'
    >;
};

export const mockSsoOidcClientOutputs = (overrides: MockedSsoOidcCommandOutputs = {}) => {
    return vi.spyOn(SSOOIDCClient.prototype, 'send').mockImplementation(async (command) => {
        const commandName =
            typeof command.constructor.getMockName === 'function'
                ? command.constructor.getMockName()
                : command.constructor.name;
        if (typeof overrides[commandName] !== 'function') {
            throw new Error(`Unknown command: ${commandName}`);
        }
        return overrides[commandName]();
    });
};
