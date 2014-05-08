#!/bin/bash

export SWIFT_HOST="10.100.46.54"
#export KEYSTONE_HOST="10.100.46.52:35357"
#export KEYSTONE_HOST="10.100.46.52:5000"
export AUTH="tempauth"

export ADMIN_TENANT="admin"

export TEST1_TENANT="CI"
export TEST1_USER="ci"
export TEST1_PASS="ci"
#export TEST1_ACCESS_KEY="b69e6fec5c724b4daee3b20b58936e45"
#export TEST1_SECRET_KEY="ad8ac1323c4741559d8edadd74e116d3"

export TEST2_TENANT="CI"
export TEST2_USER="ci2"
export TEST2_PASS="ci2"
#export TEST2_ACCESS_KEY="1c096946dbbd44019cc571b21116e0fb"
#export TEST2_SECRET_KEY="a684c43f69dc4eb0a2fa8de698600ff5"

export TEST3_TENANT="CI"
export TEST3_USER="ci3"
export TEST3_PASS="ci3"
#export TEST3_ACCESS_KEY="a4178c875d544e31bd43de53da3290a2"
#export TEST3_SECRET_KEY="be98898e48b040aaa7da815142766b61"

export TEST_DIR="/tmp/swift"

./check "$@"
