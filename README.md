# 🛡️ DriftGuard — Configuration Change Detector

A developer and DevOps platform that automatically detects configuration drift, classifies risk severity (`CRITICAL`, `MEDIUM`, `LOW`), blocks unsafe production deployments, and visualizes differences in an interactive React web dashboard.

---

## 🚀 Architecture Overview (TypeScript + React Stack)

- **Frontend:** React 19, TypeScript, Vite, Lucide Icons
- **Core Detection Engine:** Pure TypeScript recursive dictionary comparison (shared across CLI & Browser)
- **Configuration Parser:** `js-yaml`
- **Testing:** Vitest
- **CLI & Automation:** Node.js + TypeScript (`tsx`)
- **CI/CD:** GitHub Actions

---

## 🛠️ Quick Start

### 1. Install Dependencies

```powershell
npm install
```

### 2. Run the Interactive React Dashboard

```powershell
npm run dev
```

Open **`http://localhost:5173`** in your browser. The dashboard features:
- Preset scenario selector (Clean baseline vs. Critical drift vs. Policy breaches).
- Live YAML editing with real-time browser-side drift recalculation.
- Deployment readiness status (`BLOCKED` vs `PASSED`).
- Metric cards (Total, Critical Blocker, Medium, Low).
- Filterable findings table with severity color tags.
- Direct downloads for structured JSON and formatted Markdown reports.

---

## 💻 Command Line Interface (CLI)

The CLI evaluates configurations, prints a terminal summary, generates reports in `reports/`, and sets the exit code (exit code `1` on critical drift, `0` on clean state):

```powershell
# Clean baseline check (Exits with 0 - PASSED)
npm run cli

# Drifted demo check (Exits with 1 - BLOCKED)
npm run cli -- --actual config/demo-actual.yaml

# Custom files
npm run cli -- --expected path/to/expected.yaml --actual path/to/actual.yaml
```

---

## 🧪 Automated Testing

Run the full Vitest test suite:

```powershell
npm test
```

---

## 🔄 GitHub Actions CI/CD

The workflow in `.github/workflows/driftguard.yml`:
1. Sets up Node.js.
2. Installs dependencies via `npm ci`.
3. Runs the automated test suite (`npm test`).
4. Type-checks and builds the React application (`npm run build`).
5. Checks configuration drift using the CLI (`npm run cli`).
6. Uploads generated reports (`reports/drift-report.json`, `reports/drift-report.md`) as workflow artifacts.
