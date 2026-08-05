# CloudLens Installation Guide

Complete step-by-step installation instructions for CloudLens.

## 📋 Prerequisites

Before installing CloudLens, ensure you have:
- A computer running Linux (Ubuntu 20.04+ recommended), macOS (12+), or Windows with WSL2
- At least 8GB RAM (16GB recommended for AI features)
- 10GB free disk space
- Internet connection

## 🔧 Step 1: Install Required Tools

### Install Rust

CloudLens backend is written in Rust for performance and safety.

**Linux/macOS:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
rustc --version  # Should show 1.75.0 or higher
```

**Windows (PowerShell):**
```powershell
winget install Rustlang.Rustup
```

### Install Node.js

Frontend requires Node.js LTS.

**Using nvm (Linux/macOS):**
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm install --lts
node --version
npm --version
```

**Windows:**
Download from [nodejs.org](https://nodejs.org/) or use:
```powershell
winget install OpenJS.NodeJS.LTS
```

### Install Docker

Required for database services.

**Linux:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version
```

**macOS/Windows:**
Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)

### Install Just (Optional Task Runner)

```bash
cargo install just
just --list  # Show available tasks
```

## 📥 Step 2: Get CloudLens Source Code

```bash
git clone https://github.com/cloudlens-project/cloudlens.git
cd cloudlens
```

## ⚙️ Step 3: Configure Environment

Create environment file:
```bash
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Database Configuration
DATABASE_URL=postgres://cloudlens:secure_password@localhost:5432/cloudlens
NEO4J_URL=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASS=secure_neo4j_password
REDIS_URL=redis://localhost:6379

# AI Configuration (optional - leave empty for local models)
OPENAI_API_KEY=
LLM_MODEL=local-mistral
HUGGINGFACE_TOKEN=

# Cloud Provider Credentials (optional - can add via UI later)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1

AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=
AZURE_SUBSCRIPTION_ID=

GCP_PROJECT_ID=
GCP_SERVICE_ACCOUNT_KEY=

# Server Configuration
PORT=8080
FRONTEND_PORT=5173
LOG_LEVEL=info

# Security
JWT_SECRET=generate_a_secure_random_string_here
SESSION_TIMEOUT=3600
```

**Generate secure secrets:**
```bash
# Generate JWT secret
openssl rand -base64 32

# Generate database password
openssl rand -base64 24
```

## 🗄️ Step 4: Start Database Services

```bash
docker compose up -d db graph-db cache
```

Verify services are running:
```bash
docker compose ps
# Should show postgres, neo4j, and redis as "running"
```

Test connections:
```bash
# PostgreSQL
docker compose exec db psql -U cloudlens -c "SELECT 1;"

# Neo4j
docker compose exec graph-db cypher-shell -u neo4j -p secure_neo4j_password "RETURN 1;"

# Redis
docker compose exec cache redis-cli ping
# Should return PONG
```

## 🔨 Step 5: Build CloudLens

### Build Backend

```bash
cd backend

# Debug build (faster compilation)
cargo build

# Release build (optimized, recommended for production)
cargo build --release

# Verify build
./target/release/cloudlens --version
```

### Build Frontend

```bash
cd frontend

# Install dependencies
npm install

# Development build
npm run build

# Verify build
ls dist/  # Should contain index.html and assets
```

## 🚀 Step 6: Run CloudLens

### Option A: Development Mode

**Terminal 1 - Backend:**
```bash
cd backend
cargo run --release
# Should show: "Listening on http://0.0.0.0:8080"
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
# Should show: "Local: http://localhost:5173"
```

### Option B: Production Mode

```bash
# Build everything
just build-all

# Start services
just start-prod
```

Or manually:
```bash
# Backend
./backend/target/release/cloudlens serve --config production.toml

# Frontend (serve built files)
cd frontend/dist
python3 -m http.server 5173
```

## ✅ Step 7: Verify Installation

Open browser to `http://localhost:5173`

You should see the CloudLens dashboard.

**Test Demo Mode:**
1. Click "Run Simulation" button
2. Wait for graph to populate
3. Click "Analyze Risks"
4. View detected vulnerabilities

**Test CLI:**
```bash
cd backend
./target/release/cloudlens --help
./target/release/cloudlens scan --demo
```

## ☁️ Step 8: Connect Cloud Providers (Optional)

### AWS

1. Create IAM user with read-only permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "s3:GetBucket*",
      "s3:List*",
      "iam:Get*",
      "iam:List*"
    ],
    "Resource": "*"
  }]
}
```

2. Add credentials to `.env` or UI Settings

### Azure

1. Create Service Principal:
```bash
az ad sp create-for-rbac --name cloudlens-scanner --role reader
```

2. Add credentials to `.env` or UI

### GCP

1. Create service account:
```bash
gcloud iam service-accounts create cloudlens-scanner
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:cloudlens-scanner@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"
```

2. Download JSON key and add to `.env`

## 🧪 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port 8080
lsof -i :8080
# Kill it
kill -9 <PID>
```

**Docker permission denied:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Rust version too old:**
```bash
rustup update
```

**Node modules issues:**
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
```

**Database connection failed:**
```bash
# Check if containers are running
docker compose ps

# View logs
docker compose logs db
docker compose logs graph-db
```

### Getting Help

- Check [FAQ](docs/FAQ.md)
- Open an issue on GitHub
- Start a discussion in [GitHub Discussions](../../discussions)
- Email us at security@cloudlens.dev

*Note: We don't have a Discord server yet. Join the conversation on GitHub Discussions!*

## 🎉 Next Steps

Now that CloudLens is installed:

1. **Run a demo scan** to see it in action
2. **Connect your cloud providers** for real analysis
3. **Explore the 3D graph visualization**
4. **Review detected risks** and remediation steps
5. **Set up scheduled scans** for continuous monitoring

Happy securing! 🔒
