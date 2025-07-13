# Getting Started with VulnBuster

This guide will help you quickly get started with VulnBuster, from installation to running your first scan.

## 🚀 Installation

### Prerequisites

- Docker and Docker Compose (recommended)
  - [Install Docker Desktop](https://www.docker.com/products/docker-desktop/)
  - Or install [Docker Engine](https://docs.docker.com/engine/install/) and [Docker Compose](https://docs.docker.com/compose/install/) separately

- Python 3.8+ (for manual installation)
  - [Download Python](https://www.python.org/downloads/)

### Docker Installation (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/VulnBuster.git
   cd VulnBuster
   ```

2. Copy the example environment file and configure it:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

4. Access the web interface at [http://localhost:8000](http://localhost:8000)

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/VulnBuster.git
   cd VulnBuster
   ```

2. Create and activate a virtual environment:
   ```bash
   # On Unix/macOS
   python -m venv venv
   source venv/bin/activate
   
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## 🏁 Quick Start

### Running Your First Scan

1. **Web Application Scan**:
   ```bash
   vulnbuster scan https://example.com
   ```

2. **Mobile App Analysis** (Android):
   ```bash
   vulnbuster mobile-scan app.apk --platform android
   ```

3. **Cloud Security Assessment** (AWS):
   ```bash
   vulnbuster cloud-scan --provider aws --profile default
   ```

### Using the Web Interface

1. Start the web interface:
   ```bash
   vulnbuster web
   ```
   Or using Docker:
   ```bash
   docker-compose up -d
   ```

2. Open your browser to [http://localhost:8000](http://localhost:8000)

3. Create a new scan:
   - Click "New Scan"
   - Enter the target URL or upload a file
   - Select scan options
   - Click "Start Scan"

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```ini
# Web Interface
WEB_HOST=0.0.0.0
WEB_PORT=8000
SECRET_KEY=your-secret-key
DEBUG=True

# Database
DATABASE_URL=sqlite:///./vulnbuster.db

# Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme

# API Keys (if needed)
VIRUSTOTAL_API_KEY=your-virustotal-key
SHODAN_API_KEY=your-shodan-key
```

### Configuration File

You can also create a `config.yaml` file in the project root:

```yaml
web:
  host: 0.0.0.0
  port: 8000
  debug: true
  secret_key: your-secret-key

database:
  url: sqlite:///./vulnbuster.db

scanner:
  timeout: 300
  threads: 10
  user_agent: VulnBuster/1.0
  
  # Web scanner settings
  web:
    crawl_depth: 5
    follow_redirects: true
    
  # Mobile scanner settings
  mobile:
    android_sdk_path: /path/to/android/sdk
    frida_enabled: true
    
  # Cloud scanner settings
  cloud:
    aws_profile: default
    gcp_credentials: /path/to/credentials.json
```

## 📦 Available Commands

### Core Commands
- `vulnbuster scan <target>` - Scan a web application
- `vulnbuster mobile-scan <file>` - Scan a mobile application
- `vulnbuster cloud-scan` - Scan cloud infrastructure
- `vulnbuster web` - Start the web interface
- `vulnbuster api` - Start the API server

### Utility Commands
- `vulnbuster config` - Show or modify configuration
- `vulnbuster update` - Update VulnBuster to the latest version
- `vulnbuster version` - Show version information

## 🚨 Troubleshooting

### Common Issues

1. **Docker Compose Fails to Start**
   - Ensure Docker is running
   - Check available disk space
   - Try rebuilding the containers: `docker-compose build --no-cache`

2. **Python Module Not Found**
   - Ensure you've activated the virtual environment
   - Reinstall dependencies: `pip install -r requirements.txt`

3. **Scan Fails with Timeout**
   - Increase the timeout in the configuration
   - Check your internet connection
   - Verify the target is accessible

### Getting Help

- Check the [FAQ](../faq.md)
- Search the [issue tracker](https://github.com/yourusername/VulnBuster/issues)
- [Open a new issue](https://github.com/yourusername/VulnBuster/issues/new) if you can't find a solution

## ➡️ Next Steps

- Learn about [Web Application Scanning](../user-guide/web-scanning.md)
- Explore [Advanced Configuration](../user-guide/advanced-configuration.md)
- Check out [Example Use Cases](../examples/README.md)
