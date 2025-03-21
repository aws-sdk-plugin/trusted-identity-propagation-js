/**
 * Extracts the application ID from the resource part of the application ARN.
 *   Input: arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef
 *   Output: apl-1234567890abcdef
 */
export const getAppplicationIdFromArn = (applicationArn: string) => {
    return applicationArn.split('/').pop();
};

export const getBootstrapSessionName = (applicationArn: string) => {
    return `TrustedIdentityPropagationSDKPlugin-${getAppplicationIdFromArn(applicationArn)}`;
};

export const getIdentityEnhancedSessionName = (applicationArn: string) => {
    return `TrustedIdentityPropagationSDKPluginEnhanced-${getAppplicationIdFromArn(applicationArn)}`;
};
