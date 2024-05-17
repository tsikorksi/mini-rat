import socketserver
import http.server
import hashlib
import threading
# import ssl

PORT = 9998

class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(2048).strip()
        print(str(self.data, "utf-8"))



def host_commands(cmds):


    Handler = http.server.SimpleHTTPRequestHandler
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT + 1), Handler)
    # TODO: SSL
    # server.socket = ssl.wrap_socket(server.socket, certfile='', server_side= True)

    write_commands(cmds)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    print("serving at port", PORT + 1)
    server_thread.start()



def write_commands(cmds):
    f = open("commands.txt", "w")
    for cmd in cmds:
        hash = hashlib.sha256(cmd.encode("utf-8")).hexdigest()
        f.write(f"{cmd}:{hash}\n")
    f.close()


if __name__ == "__main__":
    cmds = []
    cmds.append("password:ls:/etc")
    cmds.append("password:BUILTIN:name")
    cmds.append("password:BUILTIN:cwd")
    cmds.append("password:BUILTIN:pid")

    host_commands(cmds)

    with socketserver.TCPServer(("0.0.0.0", PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print(f"Receiving at port {PORT}")
        server.serve_forever()