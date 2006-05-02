#!/bin/sh

autoconf || exit 1
automake || exit 1

./configure
