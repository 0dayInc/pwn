#!/bin/bash --login
source /etc/profile.d/globals.sh

if [[ $PWN_ROOT == '' ]]; then
  if [[ ! -d '/pwn' ]]; then
    pwn_root=$(pwd)
  else
    pwn_root='/pwn'
  fi
else
  pwn_root="${PWN_ROOT}"
fi

pwn_provider=`echo $PWN_PROVIDER`
os=$(uname -s)

case $os in
  "Darwin")
    echo 'Installing wget to retrieve tesseract trained data...'
    sudo port -N install wget

    echo "Installing fontconfig..."
    sudo port -N install fontconfig

    echo "Installing cmatrix..."
    sudo port -N install cmatrix

    echo 'Installing Postgres Libraries for pg gem...'
    sudo port -N install postgresql96-server

    echo 'Installing libpcap Libraries...'
    sudo port -N install libpcap

    echo "Installing libsndfile1 & libsndfile1-dev Libraries..."
    sudo port -N install libsndfile

    echo 'Installing ImageMagick...'
    sudo port -N install imagemagick

    echo 'Installing Tesseract OCR...'
    sudo port -N install tesseract
    sudo /bin/bash --login -c 'cd /opt/local/share/tessdata && wget https://raw.githubusercontent.com/tesseract-ocr/tessdata/master/eng.traineddata'
    ;;
  "Linux")
    apt --version > /dev/null 2>&1
    if [[ $? == 0 ]]; then
      echo "Installing wget to retrieve tesseract trained data..."
      $screen_cmd "${apt} install -y wget ${assess_update_errors}"
      grok_error

      echo "Installing fontconfig..."
      $screen_cmd "${apt} install -y fontconfig ${assess_update_errors}"
      grok_error

      echo "Installing fontmatrix..."
      $screen_cmd "${apt} install -y cmatrix-xfont ${assess_update_errors}"
      grok_error

      echo "Installing Postgres Libraries for pg gem..."
      $screen_cmd "${apt} install -y postgresql-server-dev-all ${assess_update_errors}"
      grok_error

      echo "Installing libpcap Libraries..."
      $screen_cmd "${apt} install -y libpcap-dev ${assess_update_errors}"
      grok_error

      echo "Installing fftw Libraries..."
      $screen_cmd "${apt} install -y libfftw3-dev ${assess_update_errors}"
      grok_error

      echo "Installing libsndfile1 & libsndfile1-dev Libraries..."
      $screen_cmd "${apt} install -y libsndfile1 ${assess_update_errors}"
      grok_error

      $screen_cmd "${apt} install -y libsndfile1-dev ${assess_update_errors}"
      grok_error

      echo "Installing imagemagick & libmagickwand-dev Libraries..."
      $screen_cmd "${apt} install -y imagemagick ${assess_update_errors}"
      grok_error

      $screen_cmd "${apt} install -y libmagickwand-dev ${assess_update_errors}"
      grok_error

      echo "Installing tesseract-ocr-all & trainers..."
      $screen_cmd "${apt} install -y tesseract-ocr-all ${assess_update_errors}"
      grok_error

      $screen_cmd "cd /usr/share/tesseract-ocr && wget https://raw.githubusercontent.com/tesseract-ocr/tessdata/master/eng.traineddata ${assess_update_errors}"
      grok_error
    else
      echo "A Linux Distro was Detected, however, ${0} currently only supports Kali Rolling, Ubuntu, & OSX for now...feel free to install manually."
    fi
    ;;
  *)
    echo "${os} not currently supported."
    exit 1
esac

rvmsudo /bin/bash --login -c "cd ${pwn_root} && cp etc/userland/${pwn_provider}/metasploit/vagrant.yaml.EXAMPLE etc/userland/${pwn_provider}/metasploit/vagrant.yaml && ./reinstall_pwn_gemset.sh && ./build_pwn_gem.sh && rubocop"
