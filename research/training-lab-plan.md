# Training Lab Deployment Plan

## Docker Images & Port Assignments

| App | Docker Image | Internal Port | External Port | Subdomain |
|-----|-------------|---------------|---------------|-----------|
| DVWA | `vulnerables/web-dvwa` | 80 | 8081 | dvwa.lab.aceofcloud.io |
| Juice Shop | `bkimminich/juice-shop` | 3000 | 8082 | juiceshop.lab.aceofcloud.io |
| bWAPP | `raesene/bwapp` | 80 | 8083 | bwapp.lab.aceofcloud.io |
| Mutillidae | `webpwnized/mutillidae:latest` | 80 | 8084 | mutillidae.lab.aceofcloud.io |
| WebGoat | `webgoat/webgoat` | 8080/8888 | 8085 | webgoat.lab.aceofcloud.io |
| Altoro Mutual | Build from `jrocia/AltoroMutual-Dockerfile` | 8080 | 8086 | altoro.lab.aceofcloud.io |
| Damn Vulnerable Bank | `rewanthtammana/dvb-api` + MySQL | 3000 | 8087 | dvbank.lab.aceofcloud.io |

## Droplet Specs
- Region: NYC1 (closest to scan server)
- Size: s-2vcpu-4gb ($24/mo)
- Image: Ubuntu 22.04
- Tags: training-lab, vulnerable-apps

## Architecture
- Docker Compose with all 7 apps
- Nginx reverse proxy for subdomain routing
- Each app on its own port for raw IP access
- DNS A records for *.lab.aceofcloud.io pointing to droplet IP
