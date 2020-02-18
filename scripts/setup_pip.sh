#!/bin/bash

set -ex


if [[ "${PYTHON3}" == "no" ]]; then
    TMP_VIRTUALENV="virtualenv"
else
    TMP_VIRTUALENV="python3 -m virtualenv --python=python3"
fi

# This little dance allows us to install the latest pip and setuptools
# without get_pip.py or the python-pip package (in epel on centos)
if (( $(${TMP_VIRTUALENV} --version | cut -d. -f1) >= 14 )); then
    SETUPTOOLS="--no-setuptools"
fi

# virtualenv 16.4.0 fixed symlink handling. The interaction of the new
# corrected behavior with legacy bugs in packaged virtualenv releases in
# distributions means we need to hold on to the pip bootstrap installation
# chain to preserve symlinks. As distributions upgrade their default
# installations we may not need this workaround in the future
PIPBOOTSTRAP=/var/lib/pipbootstrap

# Create the boostrap environment so we can get pip from virtualenv
${TMP_VIRTUALENV} --extra-search-dir=/tmp/wheels ${SETUPTOOLS} ${PIPBOOTSTRAP}
source ${PIPBOOTSTRAP}/bin/activate

UPPER_CONSTRAINTS_FILE=/tmp/wheels/upper-constraints.txt
if [[ "${PROJECT}" == "requirements" ]]; then
    UPPER_CONSTRAINTS_FILE=/upper-constraints.txt
fi

# Upgrade to the latest version of virtualenv
# virtualenv is also constrainted by uc, so using it here
pip install --upgrade -c ${UPPER_CONSTRAINTS_FILE} ${PIP_ARGS} virtualenv

# Forget the cached locations of python binaries
hash -r

# Create the virtualenv with the updated toolchain for openstack service
virtualenv --extra-search-dir=/tmp/wheels /var/lib/openstack

# Deactivate the old bootstrap virtualenv and switch to the new one
deactivate
source /var/lib/openstack/bin/activate
