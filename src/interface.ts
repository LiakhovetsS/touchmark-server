export type TStore = Map<string, number>;
export type TAppSecretKeyList = string[];
export type TAllowedIpList = string[];
export type TWhiteListPath = string[];
export type TPrefixList = string[];
export type TSignatureValidation = Record<string, string>;
export interface IConfig {
    applyFingerprint: boolean;
    appSecretKeyList: TAppSecretKeyList;
    allowedIpList: TAllowedIpList;
    whiteListPath: TWhiteListPath;
    assetsPathPrefixList: TPrefixList;
}
export interface IHeaders{
    [key: string]: string | undefined;
}

export enum SignatureErrorMessage {
    SIGNATURE_IS_VALID = 'Signature is valid',
    INVALID_SIGNATURE = 'Invalid signature',
    PATH_WHITE_LISTED = 'Path is whitelisted',
    IP_WHITE_LISTED = 'IP is whitelisted',
    SIGNATURE_REQUIRED = 'Signature is required',
    SIGNATURE_EXISTS_IN_CACHE = 'Signature already exists in cache',
    SIGNATURE_VALIDATION_FAILED = 'Signature validation failed',
}