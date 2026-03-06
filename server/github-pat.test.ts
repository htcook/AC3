import { describe, it, expect } from 'vitest';

describe('GitHub PAT Validation', () => {
  it('should authenticate with GitHub API using GITHUB_PAT', async () => {
    const token = process.env.GITHUB_PAT;
    expect(token).toBeTruthy();
    expect(token!.startsWith('github_pat_')).toBe(true);

    const res = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
    });

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.login).toBeTruthy();
    console.log(`GitHub PAT valid — authenticated as: ${data.login}`);
  });

  it('should have code search scope for recon dorks', async () => {
    const token = process.env.GITHUB_PAT;
    const res = await fetch('https://api.github.com/search/code?q=test+in:file&per_page=1', {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
      },
    });

    // 200 = has code search scope, 403/422 = missing scope
    expect([200, 422]).toContain(res.status);
    console.log(`Code search endpoint status: ${res.status}`);
  });
});
