export interface Env {
  /** GitHub Personal Access Token (wrangler secret put GITHUB_PERSONAL_ACCESS_TOKEN) */
  GITHUB_PERSONAL_ACCESS_TOKEN: string;
  /** GitHub API host (default: github.com) */
  GITHUB_HOST: string;
  /** OAuth Client ID (wrangler secret put OAUTH_CLIENT_ID) */
  OAUTH_CLIENT_ID: string;
  /** OAuth Client Secret (wrangler secret put OAUTH_CLIENT_SECRET) */
  OAUTH_CLIENT_SECRET: string;
}
