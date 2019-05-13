import copy
import email.utils as eut
import base64
import socket
import sys
import os
import time
import thread
import json
import threading
import datetime

# global variables
BUFFER_SIZE = 4096
admins = []
admins = []
BLACKLIST_FILE = "blacklist.txt"
max_connections = 10
MAX_CACHE_BUFFER = 3
CACHE_DIR = "./cache"
blocked = []
USERNAME_PASSWORD_FILE = "username_password.txt"
flag=0
# take command line argument
arg0=sys.argv[0]
if len(sys.argv) != 2:
    print " Ex: python %s 20002" % arg0
    print " python %s PROXY_PORT" % arg0
    flag=1
if flag:
    raise SystemExit

try:
    proxy_port = int(sys.argv[1])
except:
    print "provide proper port number"
    flag=1
if flag:
    raise SystemExit
f = open(BLACKLIST_FILE, "rb")
dir=os.path.isdir(CACHE_DIR)
data = ""
if not dir:
    os.makedirs(CACHE_DIR)

while 1:
    chunk = f.read()
    if len(chunk):
        data =data + chunk
    else:
        break
blocked = data.splitlines()
f.close()

data = ""
f = open(USERNAME_PASSWORD_FILE, "rb")
while 1:
    chunk = f.read()
    if len(chunk):
        data = data + chunk
    else:
        break
data = data.splitlines()
f.close()

for file in os.listdir(CACHE_DIR):
    os.remove(CACHE_DIR + "/" + file)

for d in data:
    admins.append(base64.b64encode(d))


def get_access(fileurl):
    if fileurl not in locks:
        lock = threading.Lock()
        locks[fileurl] = lock
    else:
        lock = locks[fileurl]
    lock.acquire()



def leave_access(fileurl):
    if fileurl not in locks:
        print "Lock problem"
        sys.exit()
    else:
        lock = locks[fileurl]
        lock.release()


def add_log(fileurl, client_addr):
    fileurl = fileurl.replace("/", "__")
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")
    if not fileurl in logs:
        logs[fileurl] = []

    logs[fileurl].append({"datetime": dt,"client": json.dumps(client_addr)})


def do_cache_or_not(fileurl):
    try:
        log_arr = logs[fileurl.replace("/", "__")]
        if len(log_arr) < 4:
            return False
        last_third = log_arr[len(log_arr) - 4]["datetime"]
        if datetime.timedelta(minutes=5)+datetime.datetime.fromtimestamp(time.mktime(last_third)) < datetime.datetime.now():
            return False
        else:
            return True
    except Exception as e:
        print e
        return False


def get_cache_details(client_addr, details):
    get_access(details["total_url"])
    add_log(details["total_url"], client_addr)
    do_cache = do_cache_or_not(details["total_url"])
    cache_path, last_mtime = get_current_cache_info(details["total_url"])
    leave_access(details["total_url"])
    details["last_mtime"] = last_mtime
    details["cache_path"] = cache_path
    details["do_cache"] = do_cache
    return details



def get_current_cache_info(fileurl):

    if fileurl.startswith("/"):
        fileurl = fileurl.replace("/", "", 1)

    cache_path = CACHE_DIR + "/" + fileurl.replace("/", "__")

    if not os.path.isfile(cache_path):
        return cache_path, None        
    else:
        last_mtime = time.strptime(time.ctime(
            os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
        return cache_path, last_mtime


def get_space_for_cache(fileurl):
    cache_files = os.listdir(CACHE_DIR)
    if len(cache_files) < MAX_CACHE_BUFFER:
        return
    for file in cache_files:
        get_access(file)
    last_mtime = min(logs[file][-1]["datetime"] for file in cache_files)
    file_to_del = [file for file in cache_files if logs[
        file][-1]["datetime"] == last_mtime][0]

    os.remove(CACHE_DIR + "/" + file_to_del)
    for file in cache_files:
        leave_access(file)


def parse_details(client_addr, client_data):
    try:
        lines = client_data.splitlines()
        while lines[len(lines) - 1] == '':
            lines.remove('')
        first_line_tokens = lines[0].split()
        url = first_line_tokens[1]

        url_pos = url.find("://")
        if url_pos == -1:
            protocol="http"
        else:
            protocol = url[:url_pos]
            url = url[(url_pos + 3):]

        path_pos = url.find("/")
        port_pos = url.find(":")
        if path_pos == -1:
            path_pos = len(url)

        if path_pos < port_pos or port_pos == -1 :
            server_url = url[0:path_pos]
            server_port = 80
        else:
            server_url = url[0:port_pos]
            server_port = int(url[(port_pos*1 + 1):path_pos])

        auth_line = [line for line in lines if "Authorization" in line]
        if not len(auth_line):
            auth_b64 = None
        else:
            auth_b64 = auth_line[0].split()[2]

        first_line_tokens[1] = url[path_pos:]
        lines[0] = ' '.join(first_line_tokens)
        client_data = "\r\n".join(lines) 
        client_data= client_data+ '\r\n\r\n'

        return {
            "protocol": protocol,"server_port": server_port,"auth_b64": auth_b64,"client_data": client_data,"total_url": url,"method": first_line_tokens[0],"server_url": server_url,
        }

    except Exception as e:
        print e
        print
        return None


def insert_if_modified(details):

    lines = details["client_data"].splitlines()
    while lines[len(lines) - 1] == '':
        lines.remove('')

    header = "If-Modified-Since: "
    header = header+time.strftime("%a %b %d %H:%M:%S %Y", details["last_mtime"])
    lines.append(header)

    details["client_data"] = "\r\n".join(lines) 
    details["client_data"]=details["client_data"]+ "\r\n\r\n"
    return details


def serve_get(client_socket, client_addr, details):
    try:
        last_mtime = details["last_mtime"]
        do_cache = details["do_cache"]
        client_data = details["client_data"]
        cache_path = details["cache_path"]

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((details["server_url"], details["server_port"]))
        server_socket.send(details["client_data"])

        reply = server_socket.recv(BUFFER_SIZE)
        if not last_mtime or  not "304 Not Modified" in reply:
            if  not do_cache:
                print "without caching serving %s to %s" % (cache_path, str(client_addr))
                while len(reply):
                    client_socket.send(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                client_socket.send("\r\n\r\n")
            else:
                print "caching file while serving %s to %s" % (cache_path, str(client_addr))
                get_space_for_cache(details["total_url"])
                get_access(details["total_url"])
                f = open(cache_path, "w+")
                # print len(reply), reply
                while len(reply):
                    client_socket.send(reply)
                    f.write(reply)
                    reply = server_socket.recv(BUFFER_SIZE)
                f.close()
                leave_access(details["total_url"])
                client_socket.send("\r\n\r\n")
        else:
            print "returning cached file %s to %s" % (cache_path, str(client_addr))
            get_access(details["total_url"])
            f = open(cache_path, 'rb')
            chunk = f.read(BUFFER_SIZE)
            while chunk:
                client_socket.send(chunk)
                chunk = f.read(BUFFER_SIZE)
            f.close()
            leave_access(details["total_url"])
            

        server_socket.close()
        client_socket.close()
        return

    except Exception as e:
        server_socket.close()
        client_socket.close()
        print e
        return

# A thread function to handle one request


def handle_one_request_(client_socket, client_addr, client_data):

    details = parse_details(client_addr, client_data)

    if not details:
        print "no any details"
        client_socket.close()
        return
    isb = True
    if not (details["server_url"] + ":" + str(details["server_port"])) in blocked:
        isb = False
    elif not details["auth_b64"]:
        isb = True
    elif details["auth_b64"] in admins:
        isb = False
    else:
        isb = True

    if isb == True:
        print "Block status : ", isb
        client_socket.send("HTTP/1.0 200 OK\r\n")
        client_socket.send("Content-Length: 11\r\n")
        client_socket.send("\r\n")
        client_socket.send("Error\r\n")
        client_socket.send("\r\n\r\n")
    else:
        if isb == False and details["method"] == "POST":
            try:
                server_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect(
                    (details["server_url"], details["server_port"]))
                server_socket.send(details["client_data"])

                while True:
                    reply = server_socket.recv(BUFFER_SIZE)
                    if len(reply):
                        client_socket.send(reply)
                    else:
                        break

                server_socket.close()
                client_socket.close()
                return

            except Exception as e:
                client_socket.close()
                server_socket.close()
                print e
                return
        else:
            if isb == False and details["method"] == "GET":
                details = get_cache_details(client_addr, details)
                if details["last_mtime"]:
                    details = insert_if_modified(details)
                serve_get(client_socket, client_addr, details)

    client_socket.close()
    print client_addr, "closed"
    print


def start_proxy_server():
    try:
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('', proxy_port))
        proxy_socket.listen(max_connections)

    except Exception as e:
        print e
        print "Error in starting proxy server ..."
        proxy_socket.close()
        raise SystemExit

    while True:
        try:
            client_socket, client_addr = proxy_socket.accept()
            client_data = client_socket.recv(BUFFER_SIZE)
            thread.start_new_thread(
                handle_one_request_, (client_socket, client_addr, client_data))

        except KeyboardInterrupt:
            client_socket.close()
            proxy_socket.close()
            print "\nProxy server shutting down ..."
            break


logs = {}
locks = {}
start_proxy_server()
