#!/bin/bash
export GIT_COMMIT_MESSAGE=$(git show -s --format=%B $GIT_COMMIT)
echo GIT_COMMIT_MESSAGE=$(echo $GIT_COMMIT_MESSAGE) > $WORKSPACE/env.properties

export JIRA_ISSUE_UPDATER_DEBUG=TRUE
echo JIRA_ISSUE_UPDATER_DEBUG=$(echo $JIRA_ISSUE_UPDATER_DEBUG) >> $WORKSPACE/env.properties

export JIRA_ISSUE_ID=$(echo $GIT_COMMIT_MESSAGE | grep -oE "issue-[0-9]+" | head -n 1)
echo JIRA_ISSUE_ID=$(echo $JIRA_ISSUE_ID) >> $WORKSPACE/env.properties

export JIRA_PROJECT=$(echo $JIRA_ISSUE_ID | sed -E 's/-[0-9]+$//g')
echo JIRA_PROJECT=$(echo $JIRA_PROJECT) >> $WORKSPACE/env.properties

export TIMESTAMP=$(date +%Y-%m-%d-%H:%M:%S-UTC)
echo TIMESTAMP=$(echo $TIMESTAMP) >> $WORKSPACE/env.properties
