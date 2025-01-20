import buildDebug from 'debug';

import { constants, pluginUtils } from '@verdaccio/core';
import { Callback, Logger } from '@verdaccio/types';
import { setupConnectionStringAuth, setupDefaultAzureCredentialAuth, setupStorageSharedKeyCredential } from './azureAuth';
import { BlobServiceClient, ContainerClient } from '@azure/storage-blob';
import { LOGGER_PREFIX } from './constants';

import {
    DEFAULT_BCRYPT_ROUNDS,
    HtpasswdHashConfig,
    addUserToHTPasswd,
    changePasswordToHTPasswd,
    parseHTPasswd,
    sanityCheck,
    stringToUtf8,
    verifyPassword,
} from './utils';

type HtpasswdHashAlgorithm = constants.HtpasswdHashAlgorithm;

const debug = buildDebug('verdaccio:plugin:htpasswdAzure');

export type HTPasswdAzureConfig = {
    algorithm?: HtpasswdHashAlgorithm;
    rounds?: number;
    max_users?: number;
    slow_verify_ms?: number;
    authMethod?: 'DefaultAzureCredential' | 'StorageSharedKeyCredential' | 'ConnectionString';
    connectionString?: string;
    accountKey?: string;
    accountName?: string;
    accountDomain?: string;
    containerName: string;
    blobName: string;
};

export const DEFAULT_SLOW_VERIFY_MS = 200;

/**
 * HTPasswd - Verdaccio auth class
 */
export default class HTPasswdAzure
    extends pluginUtils.Plugin<HTPasswdAzureConfig>
    implements pluginUtils.Auth<HTPasswdAzureConfig> {
    /**
     *
     * @param {*} config htpasswd file
     * @param {object} options config.yaml in object from
     */
    private users: {};
    private maxUsers: number;
    private hashConfig: HtpasswdHashConfig;
    private slowVerifyMs: number;
    private logger: Logger;
    private lastTime: any;
    private blobServiceClient: BlobServiceClient;
    private containerClient: ContainerClient;
    private containerName: string;
    private blobName: string;

    // constructor
    public constructor(config: HTPasswdAzureConfig, options: pluginUtils.PluginOptions) {
        super(config, options);
        this.users = {};

        // verdaccio logger
        this.logger = options.logger;

        // all this "verdaccio_config" stuff is for b/w compatibility only
        this.maxUsers = config.max_users ? config.max_users : Infinity;

        let algorithm: HtpasswdHashAlgorithm;
        let rounds: number | undefined;

        if (typeof config.algorithm === 'undefined') {
            algorithm = constants.HtpasswdHashAlgorithm.bcrypt;
        } else if (constants.HtpasswdHashAlgorithm[config.algorithm] !== undefined) {
            algorithm = constants.HtpasswdHashAlgorithm[config.algorithm];
        } else {
            this.logger.warn(
                `The algorithm selected %s is invalid, switching to to default one "bcrypt", password validation can be affected`,
                config.algorithm
            );
            algorithm = constants.HtpasswdHashAlgorithm.bcrypt;
        }
        debug(`password hash algorithm: ${algorithm}`);
        if (algorithm === constants.HtpasswdHashAlgorithm.bcrypt) {
            rounds = config.rounds || DEFAULT_BCRYPT_ROUNDS;
        } else if (config.rounds !== undefined) {
            this.logger.warn({ algo: algorithm }, 'Option "rounds" is not valid for "@{algo}" algorithm');
        }

        this.hashConfig = {
            algorithm,
            rounds,
        };

        this.lastTime = null;

        const authMethod = process.env.HTPASSWD_AZ_AUTH_METHOD || config.authMethod || 'ConnectionString';
        const containerName = process.env.HTPASSWD_AZ_CONTAINER_NAME || config.containerName;
        const accountName = process.env.HTPASSWD_AZ_ACCOUNT_NAME || config.accountName;
        const accountKey = process.env.HTPASSWD_AZ_ACCOUNT_KEY || config.accountKey;
        const accountDomain = process.env.HTPASSWD_AZ_ACCOUNT_DOMAIN || config.accountDomain || 'blob.core.windows.net';

        switch (authMethod) {
            case 'ConnectionString': {
                const { blobClient, containerClient } = setupConnectionStringAuth(
                    this.logger,
                    process.env.AZ_STORAGE_CONNECTION_STRING || config.connectionString!,
                    containerName
                );
                this.blobServiceClient = blobClient;
                this.containerClient = containerClient;
                break;
            }

            case 'DefaultAzureCredential': {
                if (!accountName) {
                    throw new Error('Account name is required!');
                }
                const { blobClient, containerClient } = setupDefaultAzureCredentialAuth(this.logger, accountName, containerName, accountDomain);
                this.blobServiceClient = blobClient;
                this.containerClient = containerClient;
                break;
            }

            case 'StorageSharedKeyCredential':
                if (!accountName) {
                    throw new Error('Account name is required!');
                }
                if (!accountKey) {
                    throw new Error('Account key is required!');
                }
                const { blobClient, containerClient } = setupStorageSharedKeyCredential(this.logger, accountName, accountKey, containerName, accountDomain);
                this.blobServiceClient = blobClient;
                this.containerClient = containerClient;
                break;

            default:
                this.logger.error(`${LOGGER_PREFIX}: Unsupported authentication method: ${authMethod}`);
                throw new Error(`Unsupported authentication method: ${authMethod}`);
        }

        this.containerName = config.containerName;
        this.blobName = config.blobName || '.htpasswd';

        if (config.slow_verify_ms) {
            this.logger.info({ ms: config.slow_verify_ms }, 'slow_verify_ms enabled for @{ms}');
        }
        this.slowVerifyMs = config.slow_verify_ms || DEFAULT_SLOW_VERIFY_MS;
    }

    /**
     * authenticate - Authenticate user.
     * @param {string} user
     * @param {string} password
     * @param {function} cb
     * @returns {void}
     */
    public authenticate(user: string, password: string, cb: Callback): void {
        debug('authenticate %s', user);
        this.reload(async (err) => {
            debug('reloaded');
            if (err) {
                if (err.statusCode === 404) {
                    debug('.htpasswd blob not found; initializing with an empty file.');
                    this.users = {}; // Reset users to an empty object
                    return cb(null, false); // User cannot be authenticated
                }
                debug('error %o', err);
                return cb(err.code === 'ENOENT' ? null : err);
            }
    
            if (!this.users[user]) {
                debug('user %s not found', user);
                return cb(null, false);
            }
    
            let passwordValid = false;
            try {
                const start = new Date();
                passwordValid = await verifyPassword(password, this.users[user]);
                const durationMs = new Date().getTime() - start.getTime();
                if (durationMs > this.slowVerifyMs) {
                    debug('password for user "%s" took %sms to verify', user, durationMs);
                    this.logger.warn(
                        { user, durationMs },
                        'Password for user "@{user}" took @{durationMs}ms to verify'
                    );
                }
            } catch (error: any) {
                this.logger.error({ message: error.message }, 'Unable to verify user password: @{message}');
            }
            if (!passwordValid) {
                debug('password invalid for %s', user);
                return cb(null, false);
            }
    
            // Authentication succeeded!
            // Return all user groups this user has access to.
            // (This particular plugin has no concept of user groups, so just return the user.)
            return cb(null, [user]);
        });
    }

    /**
     * Add user
     * 1. lock file for writing (other processes can still read)
     * 2. reload .htpasswd
     * 3. write new data into .htpasswd.tmp
     * 4. move .htpasswd.tmp to .htpasswd
     * 5. reload .htpasswd
     * 6. unlock file
     *
     * @param {string} user
     * @param {string} password
     * @param {function} realCb
     * @returns {Promise<any>}
     */
    public async adduser(user: string, password: string, realCb: Callback): Promise<any> {
        debug('adduser %s', user);
        const blockBlobClient = this.containerClient.getBlockBlobClient(this.blobName);
    
        try {
            // Ensure the blob exists before proceeding
            let blobExists = true;
            try {
                await blockBlobClient.getProperties();
            } catch (err: any) {
                if (err.statusCode === 404) {
                    debug('Blob not found; creating a new one with empty content.');
                    blobExists = false;
                    const emptyContent = '';
                    await blockBlobClient.upload(emptyContent, Buffer.byteLength(emptyContent));
                    debug('Blob created with empty content.');
                } else {
                    throw err;
                }
            }
    
            // Perform preliminary sanity checks
            let sanity = await sanityCheck(user, password, verifyPassword, this.users, this.maxUsers);
            debug('sanity check: %s', sanity);
            if (sanity) {
                debug('sanity check failed');
                return realCb(sanity, false);
            }
    
            // Acquire a lease on the blob to ensure mutual exclusion
            const leaseClient = blockBlobClient.getBlobLeaseClient();
            const leaseResponse = await leaseClient.acquireLease(15); // Lease duration: 15 seconds
            const leaseId = leaseResponse.leaseId; // Extract lease ID
            let locked = true;
    
            try {
                debug('Blob locked with lease ID: %s', leaseId);
    
                // Download the blob content
                let body = '';
                if (blobExists) {
                    const downloadResponse = await blockBlobClient.downloadToBuffer();
                    body = downloadResponse.toString('utf8');
                }
    
                // Parse users and perform final sanity check
                this.users = parseHTPasswd(body);
                debug('parsed users');
                sanity = await sanityCheck(user, password, verifyPassword, this.users, this.maxUsers);
                debug('sanity check: %s', sanity);
                if (sanity) {
                    debug('sanity check failed');
                    return realCb(sanity, false);
                }
    
                // Add the new user
                const updatedBody = await addUserToHTPasswd(body, user, password, this.hashConfig);
                debug('user added to htpasswd content');
    
                // Upload updated content to the blob
                await blockBlobClient.upload(updatedBody, Buffer.byteLength(updatedBody), {
                    conditions: { leaseId }, // Use extracted leaseId
                });
                debug('updated htpasswd content uploaded to Azure Blob Storage');
    
                // Update in-memory users
                this.users = parseHTPasswd(updatedBody);
                realCb(null, true);
            } catch (err: any) {
                debug('error %o', err);
                realCb(err, false);
            } finally {
                // Release the lease
                if (locked) {
                    try {
                        await leaseClient.releaseLease();
                        debug('Blob lease released');
                    } catch (releaseErr: any) {
                        debug('Error releasing blob lease: %o', releaseErr);
                    }
                }
            }
        } catch (err: any) {
            debug('Error in adduser: %o', err);
            realCb(err, false);
        }
    }

    /**
     * Reload users
     * @param {function} callback
     */
    public async reload(callback: Callback): Promise<void> {
        const blockBlobClient = this.containerClient.getBlockBlobClient(this.blobName);
        const logger = this.logger;
    
        logger.info(`Reloading users from Azure Blob Storage: ${this.blobName}`);
    
        try {
            const properties = await blockBlobClient.getProperties();
            const lastModified = properties.lastModified;
    
            // Check if the blob has been modified
            if (this.lastTime && lastModified && this.lastTime.getTime() === lastModified.getTime()) {
                logger.info('No changes detected in .htpasswd; skipping reload.');
                return callback(null);
            }
    
            this.lastTime = lastModified || new Date();
    
            try {
                const buffer = await blockBlobClient.downloadToBuffer();
                
                // Log raw buffer as a hexadecimal string for debugging
                logger.debug('Blob content (raw buffer as hex):', buffer.toString('hex'));
    
                if (!buffer || buffer.length === 0) {
                    throw new Error('Blob content is unexpectedly empty.');
                }
    
                // Convert buffer to UTF-8 string for parsing
                const content = buffer.toString('utf8');
                logger.debug('Blob content (UTF-8 string):', content);
    
                this.users = parseHTPasswd(content);
                logger.info(`Reloaded users: Total ${Object.keys(this.users).length}`);
                callback(null);
            } catch (err: any) {
                logger.error(`Failed to download .htpasswd: ${err.message}`);
                callback(err);
            }
        } catch (err: any) {
            logger.error(`Error checking .htpasswd blob properties: ${err.message}`);
            callback(err);
        }
    }

    private _writeFile(body: string, cb: Callback): void {
        const blockBlobClient = this.containerClient.getBlockBlobClient(this.blobName);
    
        blockBlobClient
            .upload(body, Buffer.byteLength(body))
            .then(() => {
                this.reload(() => {
                    cb(null); // Callback after reload
                });
            })
            .catch((err) => {
                this.logger.error(`Failed to write to Azure Blob Storage: ${err.message}`);
                cb(err); // Pass the error to the callback
            });
    }

    /**
     * changePassword - change password for existing user.
     * @param {string} user
     * @param {string} password
     * @param {string} newPassword
     * @param {function} realCb
     * @returns {function}
     */
    public async changePassword(
        user: string,
        password: string,
        newPassword: string,
        realCb: Callback
    ): Promise<void> {
        debug('change password %s', user);
        const blockBlobClient = this.containerClient.getBlockBlobClient(this.blobName);
    
        try {
            // Acquire a lease on the blob to ensure mutual exclusion
            const leaseClient = blockBlobClient.getBlobLeaseClient();
            const leaseResponse = await leaseClient.acquireLease(15); // Lease duration: 15 seconds
            const leaseId = leaseResponse.leaseId; // Extract leaseId
            let locked = true;
    
            try {
                debug('Blob locked with lease ID: %s', leaseId);
    
                // Download the current blob content
                let body = '';
                try {
                    const downloadResponse = await blockBlobClient.downloadToBuffer();
                    body = downloadResponse.toString('utf8');
                } catch (err: any) {
                    if (err.statusCode !== 404) {
                        throw err; // Propagate error unless it's a "blob not found" error
                    }
                    debug('Blob not found; initializing with an empty file.');
                }
    
                // Parse the current users
                this.users = parseHTPasswd(body);
    
                // Update the user's password
                const updatedBody = await changePasswordToHTPasswd(
                    body,
                    user,
                    password,
                    newPassword,
                    this.hashConfig
                );
                debug('Password updated for user %s', user);
    
                // Upload the updated content back to Azure Blob Storage
                await blockBlobClient.upload(updatedBody, Buffer.byteLength(updatedBody), {
                    conditions: { leaseId }, // Use extracted leaseId
                });
                debug('Updated htpasswd content uploaded to Azure Blob Storage');
    
                // Update in-memory users
                this.users = parseHTPasswd(updatedBody);
                realCb(null, true);
            } catch (err: any) {
                debug('Error changing password: %o', err);
                realCb(err, false);
            } finally {
                // Release the lease
                if (locked) {
                    try {
                        await leaseClient.releaseLease();
                        debug('Blob lease released');
                    } catch (releaseErr: any) {
                        debug('Error releasing blob lease: %o', releaseErr);
                    }
                }
            }
        } catch (err: any) {
            debug('Error in changePassword: %o', err);
            realCb(err, false);
        }
    }
}