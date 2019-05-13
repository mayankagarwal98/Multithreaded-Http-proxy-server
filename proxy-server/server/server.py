import sys
import os
import time
import SocketServer
import SimpleHTTPServer

flag=0
if len(sys.argv) < 1:
    print "Needs one argument: server port"
    # raise SystemExit
    flag=1


class HTTPCacheRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    def end_headers(self):
        self.send_header('Cache-control', 'must-revalidate')
        SimpleHTTPServer.SimpleHTTPRequestHandler.end_headers(self)

    def do_POST(self):
        self.send_response(200)
        self.send_header('Cache-control', 'no-cache')
        SimpleHTTPServer.SimpleHTTPRequestHandler.end_headers(self)

    def send_head(self):
        if self.command != "POST" and self.headers.get('If-Modified-Since', None):
            filename = self.path.strip("/")
            if os.path.isfile(filename):
                a = time.strptime(time.ctime(os.path.getmtime(filename)), "%a %b %d %H:%M:%S %Y")
                b = time.strptime(self.headers.get('If-Modified-Since', None), "%a %b %d %H:%M:%S %Y")
                if a < b:
                    self.send_response(304)
                    self.end_headers()
                    return None
        return SimpleHTTPServer.SimpleHTTPRequestHandler.send_head(self)
    



if flag==0 :
    PORT = 20100
    s = SocketServer.ThreadingTCPServer(("", PORT), HTTPCacheRequestHandler)
    s.allow_reuse_address = True
    print "Serving on port", PORT
    s.serve_forever()