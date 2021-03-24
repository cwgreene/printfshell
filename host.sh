#!/bin/bash
if [[ x$1 == x"" ]]; then
export IP=127.0.0.1
else
export IP="$1"
fi
socat tcp-listen:8888,reuseaddr,bind="$IP",fork exec:./a.out
