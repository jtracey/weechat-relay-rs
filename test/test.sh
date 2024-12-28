#!/bin/bash

set -e

# Runs a quick test to make sure basic functionality is working.
# This starts weechat, adds an insecure relay, then quits weechat,
# so do not run it outside of a testing environment.
if [ "$1" != "I understand what this script does." ] ; then
    echo "Do not run this script without reading and understanding it."
    exit 1
fi

weechat-headless -r '/secure set relay mypassword ; /set relay.network.password "${sec.data.relay}" ; /relay add weechat 9500' &
cargo run --features=cli -- --host localhost:9500 --init "mypassword" -s test/test.ws > test/out.txt
diff test/out.txt test/expected.txt
