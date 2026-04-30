import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Tests for the S3-compatible storage provider abstraction.
 * These test the config resolution, URL generation, and provider detection
 * without requiring actual S3 credentials.
 */

// We need to test the internal functions, so we'll import the module
// and mock the S3Client to avoid actual network calls
vi.mock('@aws-sdk/client-s3', () => ({
  S3Client: vi.fn().mockImplementation(() => ({
    send: vi.fn().mockResolvedValue({}),
  })),
  PutObjectCommand: vi.fn().mockImplementation((params) => params),
  GetObjectCommand: vi.fn().mockImplementation((params) => params),
  HeadObjectCommand: vi.fn().mockImplementation((params) => params),
  DeleteObjectCommand: vi.fn().mockImplementation((params) => params),
}));

vi.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: vi.fn().mockResolvedValue('https://signed-url.example.com/key'),
}));

describe('Storage Provider - Config Resolution & URL Generation', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    // Reset modules to clear singleton state
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Provider Detection', () => {
    it('should detect DigitalOcean Spaces from endpoint', async () => {
      process.env.S3_ENDPOINT = 'https://nyc3.digitaloceanspaces.com';
      process.env.S3_ACCESS_KEY = 'test-key';
      process.env.S3_SECRET_KEY = 'test-secret';
      process.env.S3_BUCKET = 'test-bucket';
      process.env.S3_REGION = 'nyc3';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.provider).toBe('do_spaces');
      expect(info.endpoint).toBe('https://nyc3.digitaloceanspaces.com');
    });

    it('should detect AWS S3 from endpoint', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'AKIA-test';
      process.env.S3_SECRET_KEY = 'secret-test';
      process.env.S3_BUCKET = 'my-bucket';
      process.env.S3_REGION = 'us-east-1';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.provider).toBe('aws_s3');
    });

    it('should detect MinIO from endpoint', async () => {
      process.env.S3_ENDPOINT = 'http://minio.internal:9000';
      process.env.S3_ACCESS_KEY = 'minio-key';
      process.env.S3_SECRET_KEY = 'minio-secret';
      process.env.S3_BUCKET = 'evidence';
      process.env.S3_FORCE_PATH_STYLE = 'true';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.provider).toBe('minio');
      expect(info.forcePathStyle).toBe(true);
    });

    it('should detect localhost as MinIO', async () => {
      process.env.S3_ENDPOINT = 'http://localhost:9000';
      process.env.S3_ACCESS_KEY = 'local-key';
      process.env.S3_SECRET_KEY = 'local-secret';
      process.env.S3_BUCKET = 'dev';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.provider).toBe('minio');
    });

    it('should detect custom provider for unknown endpoints', async () => {
      process.env.S3_ENDPOINT = 'https://storage.wasabi.com';
      process.env.S3_ACCESS_KEY = 'wasabi-key';
      process.env.S3_SECRET_KEY = 'wasabi-secret';
      process.env.S3_BUCKET = 'my-data';
      process.env.S3_REGION = 'us-east-2';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.provider).toBe('custom');
    });
  });

  describe('Config Priority', () => {
    it('should prefer S3_* vars over DO_SPACES_* vars', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'aws-key';
      process.env.S3_SECRET_KEY = 'aws-secret';
      process.env.S3_BUCKET = 'aws-bucket';
      process.env.S3_REGION = 'us-east-1';
      process.env.DO_SPACES_KEY = 'do-key';
      process.env.DO_SPACES_SECRET = 'do-secret';
      process.env.DO_SPACES_BUCKET = 'do-bucket';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.bucket).toBe('aws-bucket');
      expect(info.provider).toBe('aws_s3');
    });

    it('should fall back to DO_SPACES_* when S3_* not set', async () => {
      delete process.env.S3_ENDPOINT;
      delete process.env.S3_ACCESS_KEY;
      delete process.env.S3_SECRET_KEY;
      process.env.DO_SPACES_KEY = 'do-key';
      process.env.DO_SPACES_SECRET = 'do-secret';
      process.env.DO_SPACES_BUCKET = 'do-bucket';
      process.env.DO_SPACES_REGION = 'sfo3';
      process.env.DO_SPACES_ENDPOINT = 'https://sfo3.digitaloceanspaces.com';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.bucket).toBe('do-bucket');
      expect(info.region).toBe('sfo3');
      expect(info.provider).toBe('do_spaces');
    });

    it('should use default values when no env vars set', async () => {
      delete process.env.S3_ENDPOINT;
      delete process.env.S3_ACCESS_KEY;
      delete process.env.S3_SECRET_KEY;
      delete process.env.DO_SPACES_KEY;
      delete process.env.DO_SPACES_SECRET;

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.bucket).toBe('aceofcloud-reports');
      expect(info.region).toBe('nyc3');
      expect(info.hasCredentials).toBe(false);
    });
  });

  describe('URL Generation', () => {
    it('should generate DO Spaces virtual-hosted URL', async () => {
      process.env.S3_ENDPOINT = 'https://nyc3.digitaloceanspaces.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'my-bucket';
      process.env.S3_REGION = 'nyc3';

      const { doStorageGet } = await import('./do-storage');
      const { url } = await doStorageGet('reports/test.pdf');
      expect(url).toBe('https://my-bucket.nyc3.digitaloceanspaces.com/reports/test.pdf');
    });

    it('should generate AWS S3 virtual-hosted URL', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'customer-data';
      process.env.S3_REGION = 'us-east-1';

      const { doStorageGet } = await import('./do-storage');
      const { url } = await doStorageGet('evidence/screenshot.png');
      expect(url).toBe('https://customer-data.s3.us-east-1.amazonaws.com/evidence/screenshot.png');
    });

    it('should generate MinIO path-style URL', async () => {
      process.env.S3_ENDPOINT = 'http://minio.internal:9000';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'evidence';
      process.env.S3_FORCE_PATH_STYLE = 'true';

      const { doStorageGet } = await import('./do-storage');
      const { url } = await doStorageGet('scans/nuclei-output.json');
      expect(url).toBe('http://minio.internal:9000/evidence/scans/nuclei-output.json');
    });

    it('should use custom public URL base when set', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'data';
      process.env.S3_REGION = 'us-east-1';
      process.env.S3_PUBLIC_URL_BASE = 'https://cdn.aceofcloud.com';

      const { doStorageGet } = await import('./do-storage');
      const { url } = await doStorageGet('reports/final.pdf');
      expect(url).toBe('https://cdn.aceofcloud.com/reports/final.pdf');
    });

    it('should strip leading slashes from keys', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'data';
      process.env.S3_REGION = 'us-east-1';

      const { doStorageGet } = await import('./do-storage');
      const { key, url } = await doStorageGet('///leading/slashes/file.txt');
      expect(key).toBe('leading/slashes/file.txt');
      expect(url).toContain('leading/slashes/file.txt');
      expect(url).not.toContain('///');
    });
  });

  describe('Upload (doStoragePut)', () => {
    it('should upload buffer data and return URL', async () => {
      process.env.S3_ENDPOINT = 'https://nyc3.digitaloceanspaces.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'test';
      process.env.S3_REGION = 'nyc3';

      const { doStoragePut } = await import('./do-storage');
      const result = await doStoragePut('test/file.txt', Buffer.from('hello'), 'text/plain');
      expect(result.key).toBe('test/file.txt');
      expect(result.url).toBe('https://test.nyc3.digitaloceanspaces.com/test/file.txt');
    });

    it('should upload string data (auto-converts to Buffer)', async () => {
      process.env.S3_ENDPOINT = 'https://nyc3.digitaloceanspaces.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'test';
      process.env.S3_REGION = 'nyc3';

      const { doStoragePut } = await import('./do-storage');
      const result = await doStoragePut('test/string.json', '{"key":"value"}', 'application/json');
      expect(result.key).toBe('test/string.json');
      expect(result.url).toContain('test/string.json');
    });

    it('should throw when credentials are missing', async () => {
      delete process.env.S3_ENDPOINT;
      delete process.env.S3_ACCESS_KEY;
      delete process.env.S3_SECRET_KEY;
      delete process.env.DO_SPACES_KEY;
      delete process.env.DO_SPACES_SECRET;

      const { doStoragePut, resetStorageClient } = await import('./do-storage');
      resetStorageClient();
      await expect(doStoragePut('test.txt', 'data')).rejects.toThrow(/credentials missing/i);
    });
  });

  describe('Presigned URLs (doStorageGetSigned)', () => {
    it('should return a presigned URL', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'private-bucket';
      process.env.S3_REGION = 'us-east-1';

      const { doStorageGetSigned } = await import('./do-storage');
      const { url } = await doStorageGetSigned('private/file.pdf', 7200);
      expect(url).toBe('https://signed-url.example.com/key');
    });
  });

  describe('Existence Check (doStorageExists)', () => {
    it('should return true when object exists', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-east-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'key';
      process.env.S3_SECRET_KEY = 'secret';
      process.env.S3_BUCKET = 'bucket';
      process.env.S3_REGION = 'us-east-1';

      const { doStorageExists } = await import('./do-storage');
      const exists = await doStorageExists('existing-file.txt');
      expect(exists).toBe(true);
    });
  });

  describe('Storage Info (diagnostics)', () => {
    it('should return config without exposing credentials', async () => {
      process.env.S3_ENDPOINT = 'https://s3.us-gov-west-1.amazonaws.com';
      process.env.S3_ACCESS_KEY = 'SUPER_SECRET_KEY';
      process.env.S3_SECRET_KEY = 'SUPER_SECRET_VALUE';
      process.env.S3_BUCKET = 'govcloud-bucket';
      process.env.S3_REGION = 'us-gov-west-1';

      const { getStorageInfo } = await import('./do-storage');
      const info = getStorageInfo();
      expect(info.hasCredentials).toBe(true);
      expect(info.bucket).toBe('govcloud-bucket');
      expect(info.region).toBe('us-gov-west-1');
      // Verify credentials are NOT exposed
      expect(JSON.stringify(info)).not.toContain('SUPER_SECRET');
    });
  });
});
