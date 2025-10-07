#!/bin/bash

# Tauri 2.0 Migration Script
# This script automates the migration process with safety checks

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ ${NC}$1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

prompt_continue() {
    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Migration aborted by user"
        exit 1
    fi
}

# Banner
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         AI Bug Bounty Scanner - Tauri 2.0 Migration       ║"
echo "║                    Automated Migration                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Environment Check
log_info "Step 1/8: Checking environment..."

if ! command -v node &> /dev/null; then
    log_error "Node.js not found. Please install Node.js 18+"
    exit 1
fi
log_success "Node.js $(node --version) found"

if ! command -v npm &> /dev/null; then
    log_error "npm not found"
    exit 1
fi
log_success "npm $(npm --version) found"

if ! command -v rustc &> /dev/null; then
    log_error "Rust not found. Please install Rust 1.70+"
    exit 1
fi
log_success "Rust $(rustc --version | awk '{print $2}') found"

if ! command -v cargo &> /dev/null; then
    log_error "Cargo not found"
    exit 1
fi
log_success "Cargo $(cargo --version | awk '{print $2}') found"

echo ""

# Step 2: Git Status Check
log_info "Step 2/8: Checking git status..."

if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_error "Not a git repository"
    exit 1
fi

if [[ -n $(git status --porcelain) ]]; then
    log_warning "You have uncommitted changes:"
    git status --short
    echo ""
    log_warning "The migration tool requires a clean git state."
    read -p "Commit changes now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git add -A
        git commit -m "feat: Phase 1 complete - Pre Tauri 2.0 migration checkpoint"
        log_success "Changes committed"
    else
        log_error "Please commit or stash your changes first"
        exit 1
    fi
else
    log_success "Git working directory is clean"
fi

CURRENT_BRANCH=$(git branch --show-current)
log_success "Current branch: $CURRENT_BRANCH"
echo ""

# Step 3: Create Backups
log_info "Step 3/8: Creating safety backups..."

# Create backup branch
if git rev-parse --verify backup/tauri-1.6-stable &> /dev/null; then
    log_warning "Backup branch already exists, skipping creation"
else
    git checkout -b backup/tauri-1.6-stable
    log_success "Created backup branch: backup/tauri-1.6-stable"
    git checkout $CURRENT_BRANCH
fi

# Create tag
if git rev-parse v2.0.0-pre-tauri2-migration &> /dev/null; then
    log_warning "Tag already exists, skipping creation"
else
    git tag -a v2.0.0-pre-tauri2-migration -m "Phase 1 complete - Before Tauri 2.0 migration"
    log_success "Created tag: v2.0.0-pre-tauri2-migration"
fi

# Create file backup
mkdir -p ../ai-bug-bounty-scanner-backups
BACKUP_FILE="../ai-bug-bounty-scanner-backups/backup-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -czf "$BACKUP_FILE" \
    --exclude=node_modules \
    --exclude=target \
    --exclude=dist \
    --exclude=.git \
    . 2>/dev/null
log_success "Created backup: $BACKUP_FILE"
echo ""

# Step 4: Update Tauri CLI
log_info "Step 4/8: Updating Tauri CLI to latest version..."
log_warning "This will install Tauri 2.x"
prompt_continue

npm install --save-dev @tauri-apps/cli@latest
log_success "Root Tauri CLI updated"

cd frontend
npm install @tauri-apps/api@latest
npm install --save-dev @tauri-apps/cli@latest
cd ..
log_success "Frontend Tauri dependencies updated"

# Verify versions
ROOT_CLI_VERSION=$(npm list @tauri-apps/cli --depth=0 2>/dev/null | grep @tauri-apps/cli | awk -F@ '{print $NF}')
FRONTEND_API_VERSION=$(cd frontend && npm list @tauri-apps/api --depth=0 2>/dev/null | grep @tauri-apps/api | awk -F@ '{print $NF}')

log_success "Installed: @tauri-apps/cli@$ROOT_CLI_VERSION"
log_success "Installed: @tauri-apps/api@$FRONTEND_API_VERSION"
echo ""

# Step 5: Commit dependency updates
log_info "Step 5/8: Committing dependency updates..."
git add package.json package-lock.json frontend/package.json frontend/package-lock.json 2>/dev/null || true
if [[ -n $(git diff --cached) ]]; then
    git commit -m "build: Update Tauri to 2.x

- @tauri-apps/cli@$ROOT_CLI_VERSION
- @tauri-apps/api@$FRONTEND_API_VERSION"
    log_success "Dependency updates committed"
else
    log_warning "No changes to commit"
fi
echo ""

# Step 6: Run Migration Tool
log_info "Step 6/8: Running automated migration tool..."
log_warning "This will modify your source files"
prompt_continue

echo ""
log_info "Running: npm run tauri migrate"
echo ""

if npm run tauri migrate; then
    log_success "Migration tool completed successfully"
else
    log_error "Migration tool encountered errors"
    log_info "Check the output above for details"
    exit 1
fi
echo ""

# Step 7: Review Changes
log_info "Step 7/8: Reviewing migration changes..."

if [[ -f "tauri-migration-report.md" ]]; then
    log_success "Migration report generated: tauri-migration-report.md"
    echo ""
    log_info "=== Migration Report Summary ==="
    head -n 30 tauri-migration-report.md
    echo ""
    log_info "Full report available in: tauri-migration-report.md"
else
    log_warning "No migration report generated"
fi

log_info "Files modified:"
git status --short
echo ""

read -p "Review changes before committing? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git diff --stat
    echo ""
fi

# Step 8: Commit Migration
log_info "Step 8/8: Committing migration changes..."
prompt_continue

git add -A
git commit -m "build: Migrate to Tauri 2.0 (automated)

- Updated @tauri-apps/cli to 2.x
- Updated @tauri-apps/api to 2.x
- Migrated tauri.conf.json to v2 format
- Updated Cargo.toml dependencies
- Automated code pattern updates

Migration report: tauri-migration-report.md" || log_warning "Nothing to commit"

log_success "Migration changes committed"
echo ""

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              Migration Completed Successfully!             ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
log_success "Automated migration complete"
log_info "Next steps:"
echo "  1. Review migration report: tauri-migration-report.md"
echo "  2. Test compilation: cd src-tauri && cargo check"
echo "  3. Run dev server: npm run tauri dev"
echo "  4. Validate all Phase 1 features"
echo "  5. Test on both Windows and Linux"
echo ""
log_warning "Manual fixes may be required. See TAURI_2_MIGRATION_PLAN.md"
echo ""
log_info "Backups created:"
echo "  - Branch: backup/tauri-1.6-stable"
echo "  - Tag: v2.0.0-pre-tauri2-migration"
echo "  - File: $BACKUP_FILE"
echo ""
echo "Happy coding! 🚀"
echo ""
