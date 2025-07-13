# VulnBuster: Offensive Security Automation Platform

## 🚀 Docker Compose GUI Deployment

This project includes a full-stack GUI deployment using Docker Compose.

### Quick Start

1. Clone the repository and navigate to the project root.
2. (Optional) Edit `dashboard.env` to set your dashboard token and port.
3. Run:
   ```sh
   docker-compose up --build
   ```
4. Access the dashboard at [http://localhost:8000](http://localhost:8000)
5. (Optional) The reverse proxy exposes:
   - API: [http://localhost/api/](http://localhost/api/)
   - Dashboard: [http://localhost/dashboard/](http://localhost/dashboard/)

### Services
- **vulnbuster**: CLI engine, runs scans, outputs to `/app/reports`
- **dashboard**: FastAPI web dashboard, serves UI and reports
- **reverse-proxy**: (Optional) Nginx routes API and dashboard endpoints

### Volumes
- `./reports` is mounted for persistent scan/report storage

### Environment
- `dashboard.env` contains dashboard token and port config

### Requirements
- Docker and Docker Compose installed

---

For VSCode UI integration, see `vscode/README.md`. 