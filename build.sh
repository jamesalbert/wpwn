#!/usr/bin/env bash

set -e

gradle clean build install
if [[ -L wpwn ]];
then
  rm -f wpwn
fi
ln -s ./build/install/wpwn/bin/wpwn ./wpwn
