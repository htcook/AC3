/**
 * @deprecated This file is a backward-compatibility shim.
 * The canonical implementation lives in server/s3-storage.ts.
 *
 * The "DO" (DigitalOcean) naming is legacy — AC3 uses AWS S3 for all storage.
 * New code should import directly from "./s3-storage" instead.
 *
 * This shim will be removed in a future release once all imports are migrated.
 */
export {
  doStoragePut,
  doStorageGet,
  doStorageGetSigned,
  doStorageExists,
  doStorageGetContent,
  doStorageDelete,
  doStoragePutEncrypted,
  doStorageGetDecrypted,
  getStorageInfo,
  getCSEInfo,
  resetStorageClient,
  resetCSEConfig,
} from "./s3-storage";

export type { CSEMetadata } from "./s3-storage";
