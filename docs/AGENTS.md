'EOF'
# NyxOS AI Agent System

The agent system provides autonomous multi-step attack chain execution.

## Architecture
User Objective
|
v
+-------------+
| TaskPlanner | -- AI-powered task decomposition
+------+------+
v
+-------------+
| AttackChain | -- Orchestrated execution engine
+------+------+
|---> ReconAgent (OSINT + network recon)
|---> ExploitAgent (vulnerability analysis + suggestions)
+---> ReportingAgent (auto-report generation)

text

## Components

### TaskPlanner
Takes a high-level objective and breaks it into ordered sub-tasks.

### AttackChain
Executes a plan step-by-step with dependency management.

### ReconAgent
Orchestrates full OSINT + network reconnaissance.

### ExploitAgent
Analyzes findings and suggests exploitation paths.
**Never auto-exploits** — always requires user confirmation.

### ReportingAgent
Auto-generates professional reports when chains complete.

## Safety

- Every task passes through `SafetyGuard.check()` before execution
- User confirmation required at checkpoints
- All actions logged via `AuditLogger`
- Scope enforcement prevents out-of-bounds scanning
EOF
