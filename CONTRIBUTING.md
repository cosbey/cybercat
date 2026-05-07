# Contributing to CyberCat

First off — thank you for considering a contribution. CyberCat is an open-source project built by a security analyst for security analysts, and community input makes it better for everyone.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Contribution Areas](#contribution-areas)
- [Style Guidelines](#style-guidelines)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

---

## Code of Conduct

This project operates under a simple standard: be professional, be constructive, and be respectful. Contributions that are dismissive, hostile, or discriminatory will not be accepted. Security is a collaborative field — act like it.

---

## Ways to Contribute

You don't have to write code to contribute. Here are all the ways you can help:

- 🐛 **Report bugs** — open an issue with steps to reproduce
- 💡 **Suggest features** — open an issue describing the use case
- 📖 **Improve documentation** — fix typos, clarify instructions, add examples
- 🔧 **Submit code** — fix bugs, add features, improve performance
- 🛡️ **Extend the redaction engine** — add new log schema support
- 🧪 **Add test cases** — log samples that expose edge cases in redaction or parsing
- ⭐ **Star the repo** — helps others find it

---

## Getting Started

### 1. Fork and clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/cybercat.git
cd cybercat
```

### 2. Create a branch for your work

Use a descriptive branch name:

```bash
git checkout -b feature/add-splunk-schema
git checkout -b fix/redaction-unc-path-edge-case
git checkout -b docs/improve-getting-started
```

### 3. Make your changes

CyberCat is a single-file React component (`cybercat.jsx`). All logic, UI, and styling lives in that file. Open it in your editor of choice.

### 4. Test your changes

Since there's no test suite yet (contributions welcome!), test manually:

- Open the file in a Claude.ai artifact or local React environment
- Test the specific feature or fix you changed
- Test adjacent features to confirm nothing broke
- If you modified the PII redaction engine, test with sample logs from the relevant schema

### 5. Commit with a clear message

```bash
git commit -m "Add Palo Alto firewall schema to PII redaction engine"
git commit -m "Fix UNC path redaction missing trailing backslash"
git commit -m "Update README getting started for local dev"
```

---

## Submitting a Pull Request

1. Push your branch to your fork
2. Open a Pull Request against the `main` branch of this repo
3. Fill out the PR description — explain what you changed and why
4. Reference any related issues with `Closes #123` or `Related to #456`
5. Wait for review — feedback will come within a few days

### PR Checklist

Before submitting, confirm:

- [ ] My changes don't break existing features
- [ ] I've tested the affected functionality manually
- [ ] If I modified the redaction engine, I tested with relevant log samples
- [ ] My code follows the existing style (see below)
- [ ] I haven't committed any API keys, `.env` files, or real log data
- [ ] My PR description explains what changed and why

---

## Contribution Areas

### 🛡️ PII Redaction Engine — High Value

The redaction engine is the most security-critical part of CyberCat. New schema contributions are highly welcome.

To add a new schema:

1. Find the `REDACT_FIELDS` object in `cybercat.jsx`
2. Add field path → token type mappings for your schema
3. Follow the existing naming convention (`"field.path": "TOKEN_TYPE"`)
4. Add the schema to the `detectLogType()` function if it needs its own template
5. Document what the schema covers in a PR comment

**Schemas we'd love to see added:**
- CrowdStrike Falcon
- SentinelOne
- Palo Alto Networks (XSIAM / Cortex)
- QRadar
- Splunk Enterprise Security alerts
- AWS CloudTrail
- Azure Activity Logs
- Google Cloud Audit Logs

### 📧 Email Templates — Medium Value

Templates live in the `SMART_TEMPLATES` and `EMAIL_TEMPLATES` objects. Adding a new template requires:

1. A `detectLogType()` entry for the new log format
2. A field extraction map defining which log fields to pull
3. A body template function using extracted fields
4. A subject line generator

### 🎯 Threat Hunt Queries — Medium Value

The hunt query generator uses AI, but pre-seeding Claude with query patterns improves output. Contributions to the prompt templates in `LANGUAGE_PROMPTS` are welcome.

### 🖥️ UI/UX — Open

The UI is entirely CSS-in-JS. If you have design improvements, open an issue with a mockup or description before writing code so we can align on direction first.

### 📖 Documentation — Always Welcome

Better examples, clearer instructions, more log samples in the README — always appreciated. No need to ask first, just open a PR.

---

## Style Guidelines

CyberCat doesn't have a linter configured yet, but please follow the conventions already in the file:

**JavaScript:**
- Use `const` and `let`, never `var`
- Arrow functions for component definitions and callbacks
- Async/await over `.then()` chains
- Descriptive variable names — `tokenRegistry` not `tr`
- Comments for non-obvious logic, especially in the redaction engine

**React:**
- Functional components only
- `useState` and `useEffect` for state management
- No prop drilling beyond one level — lift state or pass callbacks

**CSS:**
- All colors through CSS custom properties (`var(--ap-navy)`, etc.)
- No hardcoded hex values in inline styles — use variables
- Follow the existing naming convention for new variables

**Security-specific:**
- Never log sensitive values to the console
- Any new field added to `REDACT_FIELDS` should have a comment explaining what it represents
- When in doubt, redact — false positives are safer than missed PII

---

## Reporting Bugs

Open a GitHub issue and include:

- **What you expected to happen**
- **What actually happened**
- **Steps to reproduce**
- **Log sample** (anonymized or synthetic — never real customer data)
- **Browser and version**

If the bug involves a security or privacy concern (e.g., PII not being redacted that should be), please follow the [Security Policy](SECURITY.md) instead of opening a public issue.

---

## Suggesting Features

Open a GitHub issue with the label `enhancement` and describe:

- **The problem you're trying to solve** — not just the feature
- **How you'd expect it to work** — a rough description or mockup
- **Who would benefit** — SOC analysts, IR teams, threat hunters, etc.

Feature requests are discussed before implementation. Opening an issue first saves you time writing code that might need significant changes.

---

## Questions?

Open a GitHub Discussion or drop a comment on a relevant issue. There are no dumb questions — especially when it comes to security tooling.

---

*Thanks again for contributing. Every improvement to CyberCat makes analysts' lives a little easier.*
