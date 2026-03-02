# Environment Variables Reference

When deploying Ace C3 via Docker Compose or DigitalOcean App Platform, configure these environment variables.

## Database
| Variable | Description | Default (Docker) |
|---|---|---|
| `DATABASE_URL` | MySQL connection string | `mysql://acec3:acec3_dev_pass@mysql:3306/acec3` |
| `MYSQL_ROOT_PASSWORD` | MySQL root password | `acec3_dev_root` |
| `MYSQL_DATABASE` | Database name | `acec3` |
| `MYSQL_USER` | Database user | `acec3` |
| `MYSQL_PASSWORD` | Database password | `acec3_dev_pass` |

## Infrastructure
| Variable | Description |
|---|---|
| `REDIS_URL` | Redis connection string (required for worker mode) |
| `JWT_SECRET` | Session cookie signing secret |
| `PORT` | API server port (default: 3000) |

## Caldera C2
| Variable | Description |
|---|---|
| `CALDERA_BASE_URL` | Caldera server URL |
| `CALDERA_API_KEY` | Caldera API key |
| `CALDERA_USERNAME` | Caldera login username |
| `CALDERA_PASSWORD` | Caldera login password |

## OSINT API Keys
| Variable | Description |
|---|---|
| `SHODAN_API_KEY` | Shodan API key |
| `CENSYS_API_ID` | Censys API ID |
| `CENSYS_API_SECRET` | Censys API secret |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key |
| `URLSCAN_API_KEY` | URLScan.io API key |
| `ABUSECH_API_KEY` | abuse.ch API key |

## Breach / Dark Web
| Variable | Description |
|---|---|
| `DEHASHED_API_KEY` | DeHashed API key |
| `DEHASHED_EMAIL` | DeHashed account email |

## Scanning
| Variable | Description |
|---|---|
| `GOPHISH_API_KEY` | GoPhish API key |
| `GOPHISH_BASE_URL` | GoPhish server URL |
| `ZAP_API_KEY` | OWASP ZAP API key |
| `ZAP_BASE_URL` | ZAP server URL |
| `SCAN_SERVER_HOST` | Remote scan server hostname |
| `SCAN_SERVER_USER` | SSH user for scan server |
| `SCAN_SERVER_SSH_KEY` | SSH private key for scan server |
