#!/bin/ksh
export SSLKEYLOGFILE=./sslkey.log
touch $SSLKEYLOGFILE
chmod 644 $SSLKEYLOGFILE
/usr/local/bin/jpm run --no-copy --profile /Users/andrew.mcconachie/Library/Application\ Support/Firefox/Profiles/1ih26998.bob
