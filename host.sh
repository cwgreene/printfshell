socat tcp-listen:8888,reuseaddr,fork,bind=127.0.0.1 exec:./a.out
