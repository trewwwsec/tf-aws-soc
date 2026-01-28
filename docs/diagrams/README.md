# Cloud SOC Platform - Architecture Diagrams

This directory contains architecture diagrams for the Cloud SOC Platform. All diagrams are created using Mermaid syntax, which renders automatically in GitHub, GitLab, and many documentation tools.

## 📊 Available Diagrams

1. **[High-Level Architecture](01-high-level-architecture.md)** - Overall system architecture
2. **[Network Architecture](02-network-architecture.md)** - AWS VPC and network topology
3. **[Data Flow](03-data-flow.md)** - Log collection and alert generation flow
4. **[Incident Response Workflow](04-incident-response-workflow.md)** - IR process flow
5. **[Detection Pipeline](05-detection-pipeline.md)** - How detections work end-to-end
6. **[MITRE ATT&CK Coverage](06-mitre-coverage.md)** - Visual coverage map

## 🎨 Viewing Diagrams

### On GitHub
Simply open any `.md` file - GitHub renders Mermaid diagrams automatically.

### Locally
Use a Mermaid-compatible viewer:
- **VS Code**: Install "Markdown Preview Mermaid Support" extension
- **Browser**: Use [Mermaid Live Editor](https://mermaid.live/)
- **CLI**: Use `mmdc` (mermaid-cli)

### Export to Images
```bash
# Install mermaid-cli
npm install -g @mermaid-js/mermaid-cli

# Convert to PNG
mmdc -i diagram.md -o diagram.png

# Convert to SVG
mmdc -i diagram.md -o diagram.svg
```

## 📝 Diagram Syntax

All diagrams use [Mermaid](https://mermaid.js.org/) syntax:
- **Flowcharts**: Process flows and workflows
- **Sequence Diagrams**: Interaction between components
- **Class Diagrams**: System components and relationships
- **State Diagrams**: System states and transitions
- **Network Diagrams**: Infrastructure topology

## 🎯 Use Cases

- **Portfolio**: Include in GitHub README and portfolio website
- **Documentation**: Technical documentation and runbooks
- **Presentations**: Export to images for slides
- **Training**: Onboarding new team members
- **Compliance**: Architecture documentation for audits

## 🔄 Updating Diagrams

1. Edit the Mermaid code in the `.md` file
2. Preview changes locally or on GitHub
3. Commit and push updates
4. Diagrams update automatically in documentation

---

**Last Updated**: 2026-01-28  
**Maintainer**: Cloud SOC Platform Team
