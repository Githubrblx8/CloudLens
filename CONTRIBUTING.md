# Contributing to CloudLens

Thank you for your interest in contributing to CloudLens! This document provides guidelines and instructions for contributing.

## 🎯 How to Contribute

### Reporting Bugs
- Check existing issues first
- Use the bug report template
- Include reproduction steps and environment details

### Suggesting Features
- Open a feature request issue
- Describe the use case clearly
- Explain why this feature matters for cloud security

### Code Contributions

#### 1. Fork and Clone
```bash
git clone https://github.com/cloudlens-project/cloudlens.git
cd cloudlens
```

#### 2. Create a Branch
```bash
git checkout -b feat/your-feature-name
# or
git checkout -b fix/issue-123
```

#### 3. Make Changes
Follow the coding standards:
- **Rust**: Use `cargo fmt` and `cargo clippy`
- **TypeScript**: Use `npm run lint`
- Write tests for new functionality

#### 4. Test Your Changes
```bash
# Backend tests
cd backend && cargo test

# Frontend tests
cd frontend && npm test

# Integration tests
cargo test --test integration
```

#### 5. Submit a Pull Request
- Link related issues
- Describe changes clearly
- Update documentation if needed

## 📝 Adding Security Rules

To add a new security rule:

1. Create a new file in `backend/src/rules/<category>/`
2. Implement the `SecurityRule` trait
3. Add metadata (CWE ID, MITRE ATT&CK mapping)
4. Write unit tests
5. Register the rule in the module

Example:
```rust
#[async_trait]
impl SecurityRule for MyNewRule {
    fn id(&self) -> &'static str { "CAT-001" }
    fn name(&self) -> &'static str { "My Security Rule" }
    fn severity(&self) -> RiskSeverity { RiskSeverity::High }
    
    async fn evaluate(&self, resource: &CloudResource) -> Option<SecurityRisk> {
        // Implementation
    }
}
```

## 🔌 Adding Cloud Connectors

To support a new cloud provider or service:

1. Implement the `CloudConnector` trait
2. Handle authentication securely
3. Map resources to the common model
4. Add error handling and retries
5. Write integration tests (use mock data)

## 📚 Documentation

- Update README.md if features change
- Add inline code comments
- Update API documentation in `docs/API.md`

## 🧪 Code Review Process

All contributions are reviewed by maintainers:
- Code quality and style
- Test coverage
- Security implications
- Documentation completeness

## 💬 Community

We are currently growing our community! Here's how to get involved:

- **GitHub Discussions:** Ask questions and share ideas in the [Discussions tab](../../discussions)
- **GitHub Issues:** Report bugs and request features
- **Email:** Reach out directly at security@cloudlens.dev

*Note: We don't have a Discord server yet, but we're active on GitHub Discussions. Feel free to start a conversation there!*

Thank you for making CloudLens better! 🚀
