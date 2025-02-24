import { describe, expect, it } from 'vitest';
import { fromTrustedTokenIssuer } from './fromTrustedTokenIssuer';

describe('fromTrustedTokenIssuer', () => {
    it('returns credentials', async () => {
        const result = await fromTrustedTokenIssuer({
            webTokenProvider: () => Promise.resolve(''),
            applicationArn: '',
            accessRoleArn: '',
        })();

        expect(result).toEqual({
            accessKeyId: '',
            secretAccessKey: '',
            sessionToken: '',
            expiration: expect.any(Date),
        });
    });
});
