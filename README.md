# CloudLens

**CloudLens** is a free and open-source cloud infrastructure analysis platform designed to reverse-engineer, visualize, and secure complex cloud environments. 

Just as **Ghidra** revolutionized binary reverse engineering by providing a powerful suite for disassembly and decompilation, **CloudLens** aims to become the definitive "disassembler" for modern cloud architectures. It transforms opaque infrastructure-as-code, API configurations, and runtime states into understandable, visualizable, and analyzable graphs.

---

## 🌟 Overview

Modern cloud infrastructures have become incredibly complex: hundreds of microservices, intricate IAM policies, virtual networks, container orchestration, and hidden dependencies. Understanding the true security posture of an architecture often requires deep expertise and endless command-line navigation.

**CloudLens** creates an "intelligent analysis system" capable of mapping, understanding, and explaining cloud infrastructures. It acts as a **digital microscope**, revealing hidden structures, dangerous permission paths, and misconfigurations that traditional scanners miss.

### Key Capabilities
*   **Infrastructure Disassembly:** Decompose AWS, Azure, GCP, and Kubernetes environments into fundamental components (VMs, Containers, DBs, Networks, Identities).
*   **Graph-Based Visualization:** Explore your infrastructure as an interactive 3D graph, revealing relationships between users, roles, and resources.
*   **IAM Reverse Engineering:** Trace dangerous access paths, identify privilege escalation vectors, and visualize effective permissions across complex policy chains.
*   **AI-Assisted Analysis:** Leverage integrated LLMs to explain risks, generate natural language reports, and suggest remediations (e.g., *"This configuration presents a high risk because a compromised service account can pivot to sensitive S3 buckets"*).
*   **Risk Detection Engine:** Automatically detect excessive permissions, public exposure, unprotected secrets, and network segmentation failures.

---

## 🏗️ Architecture

CloudLens follows a modular, extensible architecture similar to Ghidra's framework, allowing for custom loaders, analyzers, and visualizers.

### Core Components

| Component | Technology Stack | Description |
| :--- | :--- | :--- |
| **Frontend** | TypeScript, React, WebGL/Three.js | Interactive graph visualization, timeline exploration, and dashboard. |
| **Backend Core** | Rust / Go | High-performance graph processing, rule engine execution, and data aggregation. |
| **Analysis Agents** | Python / Go | Cloud-specific collectors (AWS Boto3, Azure SDK, K8s Client) that ingest live or static data. |
| **Storage** | PostgreSQL + Graph DB (Neo4j/TigerGraph) | Relational data for metadata; Graph DB for relationship tracing and pathfinding. |
| **AI Engine** | LLM Integration (Local/Cloud) | Natural language explanation of complex graphs and automated report generation. |

---

## 🚀 Features in Development

### 1. Intelligent Cloud Mapping
Automatically ingests data from Terraform state files, CloudFormation templates, or live cloud APIs to build a unified topology map.
*   *Supports:* EC2, Lambda, EKS, AKS, GKE, RDS, VPCs, Security Groups, IAM Roles.

### 2. Permission & Identity Analysis
Analyzes the transitive closure of permissions. It doesn't just list policies; it calculates **what actions can actually be performed** by any identity on any resource.
*   Detects privilege escalation paths.
*   Identifies overly permissive wildcard (`*`) usage.
*   Maps trust relationships between accounts and tenants.

### 3. Advanced Visualization
Move beyond spreadsheets. CloudLens renders the infrastructure as a navigable graph.
*   **Node Types:** Distinct visuals for Compute, Storage, Network, and Identity.
*   **Edge Types:** Represents traffic flow, permission grants, and ownership.
*   **Filtering:** Isolate specific sub-graphs (e.g., "Show only paths to Production Database").

### 4. AI Security Assistant
An integrated AI agent acts as a co-pilot for security engineers.
*   **Contextual Explanations:** Click any node to get an AI-generated summary of its role and risk profile.
*   **Threat Modeling:** Ask questions like *"How could an attacker move from this public-facing web server to the internal database?"* and get a step-by-step path analysis.

---

## 🛠️ Getting Started

> **Note:** CloudLens is currently in active development. The following instructions outline the planned setup process.

### Prerequisites
*   Rust (latest stable) or Go 1.20+
*   Node.js 18+ & npm/yarn
*   PostgreSQL 14+
*   Docker & Docker Compose (for Graph DB and local testing)
*   Cloud CLI tools (AWS CLI, Azure CLI, gcloud) configured with read-only credentials.

### Installation (Planned)

```bash
# Clone the repository
git clone https://github.com/cloudlens-project/cloudlens.git
cd cloudlens

# Start backend services (Database, Graph DB, API)
docker-compose up -d

# Install backend dependencies
cd backend
cargo build --release # or 'go build'

# Install frontend dependencies
cd ../frontend
npm install
npm run dev
```

### Basic Usage

1.  **Ingest Data:** Point CloudLens at a cloud account or a Terraform state file.
    ```bash
    ./cloudlens-cli ingest --provider aws --profile default --output project_alpha.cg
    ```
2.  **Launch UI:** Open the web interface to explore the generated graph.
3.  **Analyze:** Run the default rule set to identify critical risks.
4.  **Query:** Use the AI assistant or Cypher/Gremlin queries to investigate specific threat vectors.

---

## 📚 Supported Technologies

CloudLens is designed to be cloud-agnostic. Initial support focuses on:

*   **Public Clouds:** AWS, Microsoft Azure, Google Cloud Platform (GCP)
*   **Container Orchestration:** Kubernetes (EKS, AKS, GKE, Vanilla), Docker Swarm
*   **IaC Formats:** Terraform (.tfstate), CloudFormation, ARM Templates
*   **Languages:** Rust, Go, Python, TypeScript

---

## 🤝 Contributing

CloudLens is built on the philosophy that security tools should be transparent, extensible, and community-driven. We welcome contributions in:

*   **Loader Development:** Creating parsers for new cloud providers or IaC formats.
*   **Analyzer Scripts:** Writing new rules for detecting specific misconfigurations.
*   **Visualizations:** Improving the graph rendering and UX.
*   **Documentation:** Helping to explain complex cloud security concepts.

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Community & Support

*   **🐛 Issue Tracker:** Report bugs and feature requests on GitHub
*   **💬 Discussions:** Ask questions and share ideas in [GitHub Discussions](../../discussions)

*Note: We are currently growing our community. Join the conversation via GitHub Discussions or reach out directly via email.*

---

## 📄 License

This project is licensed under the MIT License, fostering a wide ecosystem of commercial and academic use, similar to Ghidra.

See [LICENSE](LICENSE) for details.

---

## 🌍 Vision

> "Modern infrastructures have become too complex to be understood solely through command lines and JSON logs. CloudLens aims to create a digital microscope capable of revealing the hidden structure and risks of the cloud."

Join us in building the future of cloud security analysis.

---

**CloudLens Team**  
*Reverse Engineering the Cloud.*
