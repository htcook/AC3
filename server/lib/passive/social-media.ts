/**
 * Social Media OSINT — Username & Organization Enumeration Connector
 *
 * Performs passive social media reconnaissance:
 * - Checks for organization presence on major platforms
 * - Discovers social media profiles linked to the domain
 * - Extracts publicly available metadata (bios, links, follower counts)
 *
 * Method: Direct HTTP checks to platform profile URLs (no API keys needed)
 * Data Source: Public profile pages on GitHub, Twitter/X, LinkedIn, etc.
 * Free: Yes — uses public profile URL probing
 */
import { createHash } from "crypto";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

interface PlatformCheck {
  platform: string;
  urlTemplate: string;
  checkMethod: "status" | "content";
}

const PLATFORMS: PlatformCheck[] = [
  { platform: "github", urlTemplate: "https://api.github.com/orgs/{name}", checkMethod: "content" },
  { platform: "github-user", urlTemplate: "https://api.github.com/users/{name}", checkMethod: "content" },
];

function extractOrgName(domain: string): string[] {
  // Extract potential organization names from domain
  const base = domain.replace(/\.(com|org|net|io|co|dev|app|xyz|info|biz|us|uk|ca|au|de|fr|jp|cn)(\.[a-z]{2})?$/i, "");
  const names = [base];
  // Also try without hyphens
  if (base.includes("-")) names.push(base.replace(/-/g, ""));
  // Also try without dots
  if (base.includes(".")) names.push(base.replace(/\./g, ""));
  return Array.from(new Set(names));
}

export const socialMediaConnector: PassiveConnector = {
  name: "social-media",
  description: "Social media OSINT — organization presence detection on GitHub, discovers public repos and org metadata",
  requiresApiKey: false,
  freeUrl: "https://github.com",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const start = Date.now();
    const errors: string[] = [];
    const observations: AssetObservation[] = [];
    const timeout = config?.timeout ?? 15000;
    let rateLimited = false;

    const orgNames = extractOrgName(domain);

    try {
      for (const orgName of orgNames) {
        // Check GitHub organization
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          const res = await fetch(`https://api.github.com/orgs/${encodeURIComponent(orgName)}`, {
            headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" },
            signal: controller.signal,
          });
          clearTimeout(timer);

          if (res.status === 403 || res.status === 429) {
            rateLimited = true;
          } else if (res.ok) {
            const data = await res.json();
            const now = new Date();
            observations.push({
              assetId: makeAssetId(domain, `github-org-${orgName}`, "social-media"),
              domain,
              assetType: "subdomain",
              name: `github.com/${orgName}`,
              source: "social-media",
              observedAt: now,
              firstSeen: data.created_at ? new Date(data.created_at) : undefined,
              tags: ["social-media", "github", "organization", "code-exposure"],
              evidence: {
                platform: "GitHub",
                profileType: "organization",
                login: data.login,
                name: data.name,
                description: data.description,
                blog: data.blog,
                location: data.location,
                email: data.email,
                publicRepos: data.public_repos,
                publicGists: data.public_gists,
                followers: data.followers,
                following: data.following,
                createdAt: data.created_at,
                updatedAt: data.updated_at,
                twitterUsername: data.twitter_username,
                isVerified: data.is_verified,
                hasOrganizationProjects: data.has_organization_projects,
                hasRepositoryProjects: data.has_repository_projects,
              },
              attribution: {
                provider: "GitHub API",
                url: `https://github.com/${orgName}`,
                method: "GitHub organization profile lookup",
                verifyUrl: `https://github.com/${orgName}`,
              },
            });

            // Also fetch public repos for code exposure analysis
            if (data.public_repos > 0) {
              await new Promise(r => setTimeout(r, 500));
              try {
                const repoRes = await fetch(
                  `https://api.github.com/orgs/${encodeURIComponent(orgName)}/repos?sort=updated&per_page=10`,
                  {
                    headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" },
                  }
                );
                if (repoRes.ok) {
                  const repos = await repoRes.json();
                  for (const repo of repos) {
                    observations.push({
                      assetId: makeAssetId(domain, `github-repo-${repo.full_name}`, "social-media"),
                      domain,
                      assetType: "url",
                      name: repo.full_name,
                      source: "social-media",
                      observedAt: now,
                      tags: [
                        "github-repo",
                        "code-exposure",
                        repo.language?.toLowerCase() || "unknown-lang",
                        repo.fork ? "fork" : "original",
                        repo.archived ? "archived" : "active",
                      ].filter(Boolean),
                      evidence: {
                        platform: "GitHub",
                        repoName: repo.name,
                        fullName: repo.full_name,
                        description: repo.description,
                        language: repo.language,
                        stars: repo.stargazers_count,
                        forks: repo.forks_count,
                        watchers: repo.watchers_count,
                        openIssues: repo.open_issues_count,
                        isPrivate: repo.private,
                        isFork: repo.fork,
                        isArchived: repo.archived,
                        defaultBranch: repo.default_branch,
                        createdAt: repo.created_at,
                        updatedAt: repo.updated_at,
                        pushedAt: repo.pushed_at,
                        topics: repo.topics,
                        homepage: repo.homepage,
                        hasWiki: repo.has_wiki,
                        hasPages: repo.has_pages,
                        license: repo.license?.spdx_id,
                      },
                      attribution: {
                        provider: "GitHub API",
                        url: `https://github.com/${repo.full_name}`,
                        method: "GitHub organization repository enumeration",
                      },
                    });
                  }
                }
              } catch {
                // Non-critical, skip
              }
            }
          }
        } catch (err: any) {
          if (err.name !== "AbortError") errors.push(`GitHub org check (${orgName}): ${err.message}`);
        }

        // Check GitHub user (if org not found)
        if (observations.filter(o => o.tags.includes("github")).length === 0) {
          try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeout);
            const res = await fetch(`https://api.github.com/users/${encodeURIComponent(orgName)}`, {
              headers: { "User-Agent": "AceStrike-DomainIntel", "Accept": "application/vnd.github.v3+json" },
              signal: controller.signal,
            });
            clearTimeout(timer);

            if (res.ok) {
              const data = await res.json();
              const now = new Date();
              observations.push({
                assetId: makeAssetId(domain, `github-user-${orgName}`, "social-media"),
                domain,
                assetType: "subdomain",
                name: `github.com/${orgName}`,
                source: "social-media",
                observedAt: now,
                tags: ["social-media", "github", "user-profile", "code-exposure"],
                evidence: {
                  platform: "GitHub",
                  profileType: "user",
                  login: data.login,
                  name: data.name,
                  bio: data.bio,
                  blog: data.blog,
                  company: data.company,
                  location: data.location,
                  email: data.email,
                  publicRepos: data.public_repos,
                  followers: data.followers,
                  twitterUsername: data.twitter_username,
                },
                attribution: {
                  provider: "GitHub API",
                  url: `https://github.com/${orgName}`,
                  method: "GitHub user profile lookup",
                },
              });
            }
          } catch {
            // Non-critical
          }
        }
      }
    } catch (err: any) {
      errors.push(`Social media OSINT error: ${err.message}`);
    }

    return {
      connector: "social-media",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
