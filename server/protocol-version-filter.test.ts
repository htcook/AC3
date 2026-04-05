/**
 * Tests for the isProtocolVersion helper that prevents HTTP protocol versions
 * (e.g., "2.0" from HTTP/2) from being stored as product versions.
 */
import { describe, it, expect } from 'vitest';
import { isProtocolVersion } from './lib/shodan-verifier';

describe('isProtocolVersion', () => {
  // Should detect HTTP protocol versions
  it('detects HTTP/2 protocol version on HTTP products', () => {
    expect(isProtocolVersion('http', '2.0')).toBe(true);
    expect(isProtocolVersion('HTTP', '2.0')).toBe(true);
    expect(isProtocolVersion('http', '2')).toBe(true);
  });

  it('detects HTTP/1.1 protocol version', () => {
    expect(isProtocolVersion('http', '1.1')).toBe(true);
    expect(isProtocolVersion('http', '1.0')).toBe(true);
  });

  it('detects protocol versions on CDN/proxy products', () => {
    expect(isProtocolVersion('cloudflare', '2.0')).toBe(true);
    expect(isProtocolVersion('akamai', '1.1')).toBe(true);
    expect(isProtocolVersion('varnish', '2.0')).toBe(true);
    expect(isProtocolVersion('fastly', '2')).toBe(true);
  });

  it('detects protocol versions on web-related products', () => {
    expect(isProtocolVersion('www', '2.0')).toBe(true);
    expect(isProtocolVersion('web server', '1.1')).toBe(true);
  });

  it('detects protocol versions on empty/unknown products', () => {
    expect(isProtocolVersion('', '2.0')).toBe(true);
    expect(isProtocolVersion('unknown', '1.1')).toBe(true);
    expect(isProtocolVersion('n/a', '2.0')).toBe(true);
  });

  // Should NOT flag real software versions
  it('allows real nginx versions', () => {
    expect(isProtocolVersion('nginx', '1.18.0')).toBe(false);
    expect(isProtocolVersion('nginx', '1.24.0')).toBe(false);
  });

  it('allows real Apache versions', () => {
    expect(isProtocolVersion('apache', '2.4.51')).toBe(false);
    expect(isProtocolVersion('Apache httpd', '2.4.41')).toBe(false);
  });

  it('allows real OpenSSH versions', () => {
    expect(isProtocolVersion('openssh', '8.9')).toBe(false);
    expect(isProtocolVersion('OpenSSH', '7.4')).toBe(false);
  });

  it('allows real MySQL versions', () => {
    expect(isProtocolVersion('mysql', '8.0.32')).toBe(false);
    expect(isProtocolVersion('MySQL', '5.7.42')).toBe(false);
  });

  it('allows real Redis versions', () => {
    expect(isProtocolVersion('redis', '7.0.11')).toBe(false);
  });

  it('allows version numbers above 3.0 on any product', () => {
    expect(isProtocolVersion('http', '4.0')).toBe(false);
    expect(isProtocolVersion('web', '10.2')).toBe(false);
  });

  it('does not flag empty versions', () => {
    expect(isProtocolVersion('nginx', '')).toBe(false);
    expect(isProtocolVersion('http', '')).toBe(false);
  });

  // Edge cases
  it('handles HTTP/3 protocol version', () => {
    expect(isProtocolVersion('http', '3')).toBe(true);
    expect(isProtocolVersion('http', '3.0')).toBe(true);
  });

  it('does not flag non-HTTP products with low versions', () => {
    // nginx 1.0 is a real version, not a protocol version
    expect(isProtocolVersion('nginx', '1.0')).toBe(false);
    // redis 2.0 is a real version
    expect(isProtocolVersion('redis', '2.0')).toBe(false);
  });
});
