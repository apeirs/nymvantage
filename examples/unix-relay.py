#!/usr/bin/env python3
"""Relay a TCP port and a Unix socket, both ways (used by netns-check.sh).

  unix-relay.py listen-unix PATH HOST:PORT   accept on a Unix socket, connect to TCP
  unix-relay.py listen-tcp HOST:PORT PATH    accept on TCP, connect to a Unix socket
"""
import os, socket, sys, threading


def pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def main():
    mode, listen, target = sys.argv[1:4]
    if mode == "listen-unix":
        srv = socket.socket(socket.AF_UNIX)
        if os.path.exists(listen):
            os.unlink(listen)
        srv.bind(listen)
        connect = lambda: socket.create_connection(hostport(target))
    else:
        srv = socket.socket(socket.AF_INET)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(hostport(listen))

        def connect():
            u = socket.socket(socket.AF_UNIX)
            u.connect(target)
            return u
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        try:
            u = connect()
        except OSError:
            c.close()
            continue
        threading.Thread(target=pipe, args=(c, u), daemon=True).start()
        threading.Thread(target=pipe, args=(u, c), daemon=True).start()


if __name__ == "__main__":
    main()
