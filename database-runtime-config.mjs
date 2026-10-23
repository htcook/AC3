const SPLIT_DATABASE_KEYS = [
  "DATABASE_HOST",
  "DATABASE_USERNAME",
  "DATABASE_PASSWORD",
  "DATABASE_NAME",
];

/**
 * Resolve the database URL without changing the process environment.
 *
 * Production ECS supplies RDS connection details as discrete values so the
 * password can remain in a dedicated Secrets Manager secret. Local and legacy
 * deployments may continue to use DATABASE_URL directly. A partial split
 * configuration is unsafe and rejected rather than silently connecting to a
 * different database.
 */
export function resolveDatabaseUrl(env = process.env) {
  const explicitUrl = env.DATABASE_URL?.trim();
  if (explicitUrl) return explicitUrl;

  const values = Object.fromEntries(
    SPLIT_DATABASE_KEYS.map((key) => [key, env[key] ?? ""]),
  );
  const configuredCount = Object.values(values).filter(Boolean).length;

  if (configuredCount === 0) return undefined;
  if (configuredCount !== SPLIT_DATABASE_KEYS.length) {
    const missing = SPLIT_DATABASE_KEYS.filter((key) => !values[key]);
    throw new Error(`Incomplete split database configuration; missing ${missing.join(", ")}`);
  }

  const portValue = env.DATABASE_PORT?.trim() || "3306";
  const port = Number(portValue);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("DATABASE_PORT must be an integer between 1 and 65535");
  }

  const url = new URL("mysql://localhost");
  url.hostname = values.DATABASE_HOST;
  url.port = String(port);
  url.username = values.DATABASE_USERNAME;
  url.password = values.DATABASE_PASSWORD;
  url.pathname = `/${values.DATABASE_NAME}`;
  return url.toString();
}
