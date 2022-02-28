#!/bin/bash
if [[ $1 != "" && $2 != "" && $3 != "" ]]; then
  # Default Strategy is to merge codebase
  git config pull.rebase false
  git config commit.gpgsign true
  git pull
  git add . --all
  echo 'Updating Gems to Latest Versions in Gemfile...'
  ./find_latest_gem_versions_per_Gemfile.sh
  pwn_autoinc_version
  git commit -a -S --author="${1} <${2}>" -m "${3}"
  ./update_pwn.sh
  # Tag for every 100 commits (i.e. 0.1.100, 0.1.200, etc)
  tag_this_version_bool=`ruby -r 'pwn' -e 'if PWN::VERSION.split(".")[-1].to_i % 100 == 0; then print true; else print false; end'`
  if [[ $tag_this_version_bool == 'true' ]]; then
    this_version=`ruby -r 'pwn' -e 'print PWN::VERSION'`
    echo "Tagging: ${this_version}"
    git tag $this_version
  fi
else
  echo "USAGE: ${0} '<full name>' <email address> '<git commit comments>'"
fi
