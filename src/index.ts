import crypto from 'node:crypto';
import {
    IConfig, IHeaders, SignatureErrorMessage,
    TAllowedIpList,
    TAppSecretKeyList,
    TPrefixList,
    TSignatureValidation,
    TStore,
    TWhiteListPath
} from "./interface";

class FingerprintCore {
    private readonly SECOND_ALLOWED: number = 10_000; // 10 seconds
    private readonly SIGNATURE_CACHE_SIZE: number = 2;
    private readonly APP_SECRET_KEY_LIST: TAppSecretKeyList = [];
    private readonly ALLOWED_IP_LIST: TAllowedIpList = [];
    private readonly WHITE_LIST_PATH: TWhiteListPath = [];
    private readonly ASSETS_PATH_PREFIX_LIST: TPrefixList = [];
    private readonly signatureValidationType: TSignatureValidation = {
        'true': SignatureErrorMessage.SIGNATURE_IS_VALID,
        'false': SignatureErrorMessage.INVALID_SIGNATURE,
    }

    private readonly applyFingerprint: boolean = false;
    private signatureCache: TStore = new Map();
    private readonly headerSignatureKey: string = 'x-request-uuid';

    constructor(options: IConfig) {
        this.applyFingerprint = options.applyFingerprint;
        this.APP_SECRET_KEY_LIST = options.appSecretKeyList;
        this.ALLOWED_IP_LIST = options.allowedIpList;
        this.WHITE_LIST_PATH = options.whiteListPath;
        this.ASSETS_PATH_PREFIX_LIST = options.assetsPathPrefixList;
        this.headerSignatureKey=options.headerSignatureKey
    }

    get isFilterInit(): boolean {
        return this.applyFingerprint;
    }

    /**
     * @method decrypt
     * @description Метод для перевірки підпису запиту
     * @param {Object} options - Параметри запиту
     * @param {string} options.method - HTTP метод запиту (GET, POST, PUT, DELETE тощо)
     * @param {string} options.path - Шлях запиту
     * @param {Object} options.headers - Заголовки запиту
     * @returns {{status: boolean, message: (*|string)}} - Повертає true, якщо запит є дійсним, інакше false
     * @throws {ApiError} - Викидає помилку ApiError, якщо запит недійсний
     * @example
     * */
    public decrypt({method = '', path = '', headers = {}}: { method: string; path: string; headers: IHeaders }): {
        status: boolean;
        message: string
    } {
        // Перевірка наявності методу, шляху та заголовків
        const isWhiteListed = this.isWhiteListedPath(path);
        if (isWhiteListed) return {status: true, message: SignatureErrorMessage.PATH_WHITE_LISTED};

        // Перевірка наявності IP-адреси в білому списку
        const ip: string = headers['x-real-ip'] || headers['x-forwarded-for'] || '';
        const isWhiteListedIP = this.isWhiteListedIP(ip);
        if (isWhiteListedIP) return {status: true, message: SignatureErrorMessage.IP_WHITE_LISTED};

        const userAgent: string = headers['user-agent'] ? headers['user-agent'].replace(/\s+/g, '') : '';
        const receivedSignature = headers[this.headerSignatureKey] || '';
        if (this.isFilterInit && !receivedSignature) return {
            status: false,
            message: SignatureErrorMessage.SIGNATURE_REQUIRED
        };

        const decodedSignature = Buffer.from(receivedSignature, 'base64').toString('utf8');
        const [timestampFromSignature, receivedSignatureFromSignature] = decodedSignature.split('_');
        const timestamp = Number(timestampFromSignature) || Date.now();

        if (this.isFilterInit && this.searchSignatureCache({
            timestamp,
            signature: receivedSignature
        })) return {
            status: false,
            message: `${SignatureErrorMessage.SIGNATURE_EXISTS_IN_CACHE}: ${receivedSignature}`
        };

        const isValid = this.isValidSignature({
            timestamp,
            method,
            path,
            receivedSignature: receivedSignatureFromSignature,
            userAgent
        });
        return {
            status: isValid,
            message: this.signatureValidationType[String(isValid)] || SignatureErrorMessage.SIGNATURE_VALIDATION_FAILED
        };
    }

    /**
     * @method #isWhiteListedPath
     * @description Перевіряє, чи є шлях запиту в білому списку
     * @param {string} path - Шлях запиту
     * @returns {boolean} - Повертає true, якщо шлях в білому списку, інакше false
     * @private
     * */
    private isWhiteListedPath(path: string): boolean {
        if (this.ASSETS_PATH_PREFIX_LIST.some(assetPath => path.startsWith(assetPath))) return true;
        return this.WHITE_LIST_PATH.some(whitePath => {
            const regex = new RegExp(`^${whitePath.replace(/:\w+/g, '[^/]+')}$`);
            return regex.test(path);
        });
    }

    /**
     * @method isWhiteListedIP
     * @description Перевіряє, чи є IP-адреса в білому списку
     * @param {string} ip - IP-адреса запиту
     * @returns {boolean} - Повертає true, якщо IP-адреса в білому списку, інакше false
     * @private
     * */
    private isWhiteListedIP(ip: string): boolean {
        if (this.ALLOWED_IP_LIST.length === 0) return true;
        return this.ALLOWED_IP_LIST.includes(ip);
    }


    /**
     * @method #isValidSignature
     * @description Checks if the request signature is valid
     * @param {Object} options - Request parameters
     * @param {string} options.timestamp - Request timestamp
     * @param {string} options.method - HTTP request method
     * @param {string} options.path - Request path
     * @param {string} options.receivedSignature - Received request signature
     * @param {string} options.userAgent - Request User-Agent
     * @returns {boolean} - Returns true if the signature is valid, otherwise false
     * @throws {ApiError} - Throws an ApiError if the signature is invalid
     * @private
     * */
    private isValidSignature({timestamp, method, path, receivedSignature, userAgent}: {
        timestamp: number;
        method: string;
        path: string;
        receivedSignature: string;
        userAgent: string
    }): boolean {
        const message = `${method.toLowerCase()}:${path}:${timestamp}:${userAgent}`;
        return this.APP_SECRET_KEY_LIST.some(secret => {
            const hmac = crypto.createHmac('sha256', secret);
            hmac.update(message);
            const expected = hmac.digest('hex');

            try {
                const expectedBuf = Buffer.from(expected, 'hex');
                const receivedBuf = Buffer.from(receivedSignature, 'hex');

                // Перевірка таймінг-атак
                return (
                    expectedBuf.length === receivedBuf.length &&
                    crypto.timingSafeEqual(expectedBuf, receivedBuf)
                );
            } catch (ex) {
                return false;
            }
        });
    }

    /**
     * @description Validate the request signature
     * * @param {Object} params - The parameters for signature validation
     * * @param {number} params.timestamp - The timestamp of the request
     * * @param {string} params.signature - The signature to validate
     * @returns {boolean} - Returns true if the signature is valid, false otherwise
     * */
    private searchSignatureCache({timestamp, signature}: { timestamp: number; signature: string }): boolean {
        if (isNaN(new Date(timestamp).getTime()) || typeof timestamp !== 'number' || timestamp <= 0) return true;
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (currentTimestamp - timestamp > this.SECOND_ALLOWED) return true;

        if (!this.signatureCache.has(signature)) {
            this.signatureCache.set(signature, 1);
            return false;
        }
        const cacheValue = this.signatureCache.get(signature) as number;
        if (cacheValue <= this.SIGNATURE_CACHE_SIZE) {
            this.signatureCache.set(signature, cacheValue + 1);
            return false;
        }

        return true;
    }
}

export = FingerprintCore;
