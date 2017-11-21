#!/bin/bash

# Dependencies
systemdeps="python2.7 python-dev python-pip ssdeep libfuzzy-dev git cmake"
pythondeps="pycrypto distorm3 pefile ssdeep fuzzyhashlib"

# Install system dependencies
apt-get install -y $systemdeps

# Install python dependencies
pip install $pythondeps

# Install TLSH
git clone "https://github.com/trendmicro/tlsh.git" /tmp/tlsh/
oldpwd=$(pwd)
cd /tmp/tlsh/
./make.sh
cd py_ext
python setup.py build
python setup.py install
cd $oldpwd
rm -rf /tmp/tlsh/