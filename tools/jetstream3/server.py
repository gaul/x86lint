#!/usr/bin/env python3
"""Serve a JetStream 3 checkout and record the POST it makes when it finishes.

JetStream's browser driver, given ?report=true, POSTs its results JSON to
/report on the origin it was served from when the last workload is done.
That request is the completion signal: the runner waits for the report file
to appear, then stops the browser.

Usage: server.py --dir JETSTREAM --port PORT --report FILE --log FILE
A port of 0 picks a free one; the chosen port is printed on stdout.
"""

import argparse
import functools
import http.server
import sys
import time


class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        '.wasm': 'application/wasm',
        '.js': 'text/javascript',
        '.mjs': 'text/javascript',
        '.json': 'application/json',
        '.z': 'application/octet-stream',
    }

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if self.path.startswith('/report'):
            with open(self.server.report_path, 'wb') as f:
                f.write(body)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', '2')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, fmt, *args):
        with open(self.server.log_path, 'a') as f:
            f.write('%s %s\n' % (time.strftime('%H:%M:%S'), fmt % args))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True)
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--report', required=True)
    ap.add_argument('--log', required=True)
    args = ap.parse_args()

    handler = functools.partial(Handler, directory=args.dir)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), handler)
    server.report_path = args.report
    server.log_path = args.log
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == '__main__':
    sys.exit(main())
