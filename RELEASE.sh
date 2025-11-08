#!/bin/bash
# Quick release script for @awth/pq-jwt (TypeScript)
# Usage: ./RELEASE.sh 0.2.0

set -e

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.2.0"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting release process for version ${VERSION}${NC}\n"

# Check if on main/trunk branch
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ] && [ "$BRANCH" != "trunk" ] && [ "$BRANCH" != "master" ]; then
    echo -e "${RED}❌ Error: Not on main branch (currently on: $BRANCH)${NC}"
    echo "Switch to main: git checkout main"
    exit 1
fi

# Check if working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo -e "${RED}❌ Error: Working directory not clean${NC}"
    echo "Commit or stash your changes first"
    exit 1
fi

# Pull latest changes
echo -e "${YELLOW}📥 Pulling latest changes...${NC}"
git pull origin $BRANCH

# Run tests
echo -e "${YELLOW}🧪 Running tests...${NC}"
bun test || {
    echo -e "${RED}❌ Tests failed${NC}"
    exit 1
}

# Update version in package.json
echo -e "${YELLOW}📝 Updating package.json version...${NC}"
CURRENT_VERSION=$(node -p "require('./package.json').version")
echo "Current version: $CURRENT_VERSION"
echo "New version: $VERSION"

if [ "$CURRENT_VERSION" == "$VERSION" ]; then
    echo -e "${RED}❌ Error: Version $VERSION is the same as current version${NC}"
    exit 1
fi

# Update version in package.json using sed (cross-platform)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$VERSION\"/" package.json
else
    # Linux
    sed -i "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$VERSION\"/" package.json
fi

# Build the project
echo -e "${YELLOW}🏗️  Building project...${NC}"
bun run build || {
    echo -e "${RED}❌ Build failed${NC}"
    # Revert changes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    else
        sed -i "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    fi
    exit 1
}

# Test the build
echo -e "${YELLOW}🧪 Testing build...${NC}"
if [ ! -f "dist/index.js" ]; then
    echo -e "${RED}❌ Build verification failed: dist/index.js not found${NC}"
    # Revert changes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    else
        sed -i "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    fi
    exit 1
fi

# Dry run npm publish
echo -e "${YELLOW}🏗️  Dry run publish...${NC}"
npm publish --dry-run || {
    echo -e "${RED}❌ Dry run publish failed${NC}"
    # Revert changes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    else
        sed -i "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    fi
    exit 1
}

# Show diff
echo -e "${YELLOW}📋 Changes to be committed:${NC}"
git diff package.json

# Confirm
echo ""
read -p "$(echo -e ${YELLOW}Continue with release? [y/N]: ${NC})" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ Release cancelled${NC}"
    # Revert changes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    else
        sed -i "s/\"version\": \"$VERSION\"/\"version\": \"$CURRENT_VERSION\"/" package.json
    fi
    exit 1
fi

# Commit changes
echo -e "${YELLOW}💾 Committing changes...${NC}"
git add package.json
git commit -m "chore: bump version to $VERSION"

# Create tag
echo -e "${YELLOW}🏷️  Creating tag v$VERSION...${NC}"
git tag -a "v$VERSION" -m "Release version $VERSION"

# Push changes
echo -e "${YELLOW}📤 Pushing to GitHub...${NC}"
git push origin $BRANCH
git push origin "v$VERSION"

# Publish to npm
echo -e "${YELLOW}📦 Publishing to npm...${NC}"
npm publish || {
    echo -e "${RED}❌ npm publish failed${NC}"
    echo "You may need to manually publish with: npm publish"
    exit 1
}

echo ""
echo -e "${GREEN}✅ Release process completed!${NC}"
echo ""
echo "Next steps:"
echo "1. Check npm: https://www.npmjs.com/package/@awth/pq-jwt"
echo "2. Verify GitHub Release: https://github.com/MKSinghDev/pq-jwt-ts/releases"
echo ""
echo -e "${GREEN}🎉 Version $VERSION has been published to npm!${NC}"
