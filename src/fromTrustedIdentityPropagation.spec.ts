import { describe, expect, it } from 'vitest';
import { fromTrustedIdentityPropagation } from './fromTrustedIdentityPropagation';

describe('fromTrustedIdentityPropagation', () => {
    it('returns credentials', () => {
        const result = fromTrustedIdentityPropagation();
        expect(result).toEqual({
            AccessKeyId: '',
            SecretAccessKey: '',
            SessionToken: '',
        });
    });
});
