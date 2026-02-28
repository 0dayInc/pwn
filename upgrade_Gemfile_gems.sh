#!/bin/bash --login
export rvmsudo_secure_path=1
rvmsudo gem update --system

cat Gemfile | awk '{print $2}' | grep -E "^'.+$" | grep -v -e rubygems.org | while read gem; do 
  this_gem=`echo $gem | sed "s/'//g" | sed 's/\,//g'`
  echo "${this_gem} => $latest_version"
  if [[ $this_gem == 'rdoc' ]]; then
    echo 'rdoc is now bundled with Ruby. Ignorning version checks in Gemfile to avoid version mismatch issues.'
    latest_version=`gem list rdoc | sed 's/[(|)]//g' | sed 's/,/ /g' | awk '{print $2}'`
    sed -i "s/^gem '${this_gem}'.*$/gem '${this_gem}', '${latest_version}'/g" Gemfile
  elif [[ $this_gem == 'json' ]]; then
    # Shakes fist at selenium-webdriver
    sed -i "s/^gem '${this_gem}'.*$/gem '${this_gem}', '>=2.13.2'/g" Gemfile
  elif [[ $this_gem == 'activesupport' ]]; then
    latest_version=`gem search -r $this_gem | grep -E "^${this_gem}\s.+$" | awk '{print $2}' | sed 's/(//g' | sed 's/)//g' | sed 's/,//g'`
    sed -i "s/^gem '${this_gem}'.*$/gem '${this_gem}', '<${latest_version}'/g" Gemfile
  elif [[ $this_gem == 'bundler' || $this_gem == 'bundler-audit' ]]; then
    latest_version=`gem search -r $this_gem | grep -E "^${this_gem}\s.+$" | awk '{print $2}' | sed 's/(//g' | sed 's/)//g' | sed 's/,//g'`
    sed -i "s/^gem '${this_gem}'.*$/gem '${this_gem}', '>=${latest_version}'/g" Gemfile
  else
    latest_version=`gem search -r $this_gem | grep -E "^${this_gem}\s.+$" | awk '{print $2}' | sed 's/(//g' | sed 's/)//g' | sed 's/,//g'`
    sed -i "s/^gem '${this_gem}'.*$/gem '${this_gem}', '${latest_version}'/g" Gemfile
  fi
done
