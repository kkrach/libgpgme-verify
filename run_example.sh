#!/bin/bash

set -e

echo "#######################################################"
echo "Example with valid clearsign signature..."
# created with gpg --clearsign text.xml
./example files/license.xml.clearsign
echo
echo

echo "#######################################################"
echo "Example with invalid clearsign signature..."
# created with gpg --clearsign text.xml
./example files/corrupt_license.xml.clearsign || true
echo
echo


echo "#######################################################"
echo "Example with valid armored signature..."
./example files/license.xml.asc files/license.xml
echo
echo

echo "#######################################################"
echo "Example with invalid armored signature..."
./example files/license.xml.asc files/corrupt_license.xml || true
echo
echo


echo "#######################################################"
echo "Example with valid binary signature..."
./example files/license.xml.gpg files/license.xml
echo
echo

echo "#######################################################"
echo "Example with invalid binary signature..."
./example files/license.xml.gpg files/corrupt_license.xml || true
echo
echo
