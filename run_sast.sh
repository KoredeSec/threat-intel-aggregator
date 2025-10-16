#!/bin/bash
# ================================================
# Full Python SAST Scan Script
# Tools: bandit, safety, pip-audit, 
# ================================================

# -------------------- Config --------------------
PROJECT_DIR=$(pwd)
REPORT_DIR="$PROJECT_DIR/sast_reports"
TIMESTAMP=$(date +"%Y%m%dT%H%M%S")
mkdir -p "$REPORT_DIR"

# -------------------- Install Tools --------------------
echo "Installing/ensuring SAST tools are available..."
pip install --upgrade pip
pip install bandit safety  pip-audit

# -------------------- Bandit --------------------
echo "Running Bandit..."
bandit -r "$PROJECT_DIR" -f html -o "$REPORT_DIR/bandit_report_$TIMESTAMP.html" --exclude "$PROJECT_DIR/threat-intel/lib"

# -------------------- Safety --------------------
echo "Running Safety..."
safety scan -r requirements.txt --json > "$REPORT_DIR/safety_report_$TIMESTAMP.json" 2>/dev/null || echo "No requirements.txt or error with Safety"

# -------------------- pip-audit --------------------
echo "Running pip-audit..."
pip-audit -f json > "$REPORT_DIR/pip_audit_report_$TIMESTAMP.json"


# -------------------- Summary --------------------
echo "------------------------------------"
echo "✅ SAST scans completed. Reports saved in $REPORT_DIR"
echo " - Bandit HTML: $REPORT_DIR/bandit_report_$TIMESTAMP.html"
echo " - Safety JSON: $REPORT_DIR/safety_report_$TIMESTAMP.json"
echo " - pip-audit JSON: $REPORT_DIR/pip_audit_report_$TIMESTAMP.json"
echo "------------------------------------"
