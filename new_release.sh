#! /bin/bash

# Script to create a new release.
#
# Creates a commit containing only the CHANGELOG and cabal file changes.
#
# Checks the state of the repository to make sure things are up to date
# beforehand, and also checks the current build status on travis.
#
# Nothing project-specific. Should work for any project on github which
# is set up to use travis.

#set -x
set -e
cd `dirname $0`

NEW_VERSION="$1"
BRANCH="$2"
[ -z "$BRANCH" ] && BRANCH="master"
SLUG=`git config -l | grep remote.origin.url | sed s/.*:// | sed s/\.git//`
PROJECT=`echo $SLUG | sed 's/.*\///'`

function opt_exit {
    read -t 30 -p "Do you want to continue (y/n) ? " yn
    case ${yn:0:1} in
        y|Y )
            echo "Continuing..."
        ;;
        * )
            exit 1
        ;;
    esac
}

git status -b -s | grep -q "## $BRANCH" \
    || ( echo "Not on $BRANCH branch."; exit 1 )

[ -f "$PROJECT.cabal" ] \
    || ( echo "Cabal file not found for $PROJECT."; exit 1 )

[ -z "$NEW_VERSION" ] \
    && ( echo "Please provide new version for the release."; exit 1 )

# The only uncommitted change at this stage should be the CHANGELOG
git status -s --untracked-files=no | grep -v 'CHANGELOG' \
    && ( echo "There are uncommitted changes. Make sure changes are committed or stashed and pushed, and the CI build is OK."; exit 1 )

git status -s | grep '??' \
    && ( echo "There are untracked files in the repository."; opt_exit )

# Make sure we have latest changes and check we are up to date with origin
git fetch origin

[ `git rev-list HEAD...origin/$BRANCH --count` = "0" ] \
    || ( echo "$BRANCH is different from origin/$BRANCH"; opt_exit )

git tag | grep -q "$NEW_VERSION" \
    && ( echo "A git tag matching $NEW_VERSION already exists."; exit 1 )

grep -q "$NEW_VERSION" CHANGELOG.md \
    || ( echo "Please add a changelog entry for this release."; exit 1 )

echo "Checking CI build state..."
curl -H "Accept: application/vnd.travis-ci.2+json" \
    "https://api.travis-ci.org/repos/$SLUG" \
    | python -m json.tool \
    | grep "last_build_state" | grep "passed" \
    || ( echo "Can't confirm that travis CI is in 'passed' state."; opt_exit )


perl -i -p -e 's/^([vV]ersion:\s+)\d.*/${1}'"$NEW_VERSION"'/' "$PROJECT.cabal"

git add "$PROJECT.cabal"
git add CHANGELOG.md

git commit -m "Release $NEW_VERSION"
git tag -m "Release $NEW_VERSION" -s "$NEW_VERSION" \
    || ( echo "Failed to tag release."; exit 1 )

echo "No remote changes yet. Next step will push the changes."
opt_exit

git push
git push --tags

