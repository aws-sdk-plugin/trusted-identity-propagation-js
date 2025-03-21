import { describe, expect, it } from 'vitest';
import { generateApplicationArn, generateApplicationId } from '../tests/helpers';
import { getAppplicationIdFromArn, getBootstrapSessionName, getIdentityEnhancedSessionName } from './helpers';

describe('getAppplicationIdFromArn', () => {
    it('returns application ID from the application ARN', () => {
        const applicationId = generateApplicationId();
        const applicationArn = generateApplicationArn(applicationId);
        const result = getAppplicationIdFromArn(applicationArn);

        expect(result).toEqual(applicationId);
    });
});

describe('getBootstrapSessionName', () => {
    it('returns expected session name', () => {
        const applicationId = generateApplicationId();
        const applicationArn = generateApplicationArn(applicationId);
        const result = getBootstrapSessionName(applicationArn);

        expect(result).toEqual(`TrustedIdentityPropagationSDKPlugin-${applicationId}`);
    });
});

describe('getIdentityEnhancedSessionName', () => {
    it('returns expected session name', () => {
        const applicationId = generateApplicationId();
        const applicationArn = generateApplicationArn(applicationId);
        const result = getIdentityEnhancedSessionName(applicationArn);

        expect(result).toEqual(`TrustedIdentityPropagationSDKPluginEnhanced-${applicationId}`);
    });
});
