# Fetchzer

-   Difficuilty : Medium
-   Category : Android

# Writeup

-   Go to the site and download the APK
-   Either using an andoid VM or a physical rooted andoid device, install the APK.
-   Add the hostname fetchzer.hashx to `/etc/hosts` for the app to be able to connect back to the api.

```bash
# If the file sytem is Read-Only, remnount it first
su
mount -o remount,rw /

# then add the dns entry
echo '<ip>     fetchzer.int' >> /etc/hosts
```

-   Intercept the traffic going to the api from the app using wireshark and find out the `xor_token` in the /api/getQuotes endpoint

```conf
192.168.1.4 - - [23/Aug/2023 00:07:44] "GET /api/getQuotes?xor_token=MDUzOTFmMWEzMjM5MjgzZTNlMzc0MzI1MzcwNzViNTAwZTI4MzQ0NzM5MGMxODVmMDY1YjE0NmQ1NjM2  HTTP/1.1" 200 -
```

-   Create a personal token from the app by providing a token secret.

```
token secret : thisiskavigihan
XOR encrypted token : MzgxZjIyMjAxYzE4MGEwYjAxMjUxMDIyM2IxNDA1

```

-   Given that this token is encrypted with XOR, use the token secret you provided and the encrypted token you get from the the app to find out the token secret by xoring them with each other.

```bash
➜ app echo -n MzgxZjIyMjAxYzE4MGEwYjAxMjUxMDIyM2IxNDA1|base64 -d |xxd -r -p|xortool-xor -s 'thisiskavigihan' -f -
LwKSukajwLwKSuk
```

-   Here we can see the string `LwKSukajw` is repeating. This is because our `access_token` is longer than the secret string we are xoring it with. Therefore, we need to identify the correct secret key as `LwKSukajw`

-   Use the discovered token secret to find out the token secret of the encrypted token we found earlier.

```bash
➜  app echo -n MDUzOTFmMWEzMjM5MjgzZTNlMzc0MzI1MzcwNzViNTAwZTI4MzQ0NzM5MGMxODVmMDY1YjE0NmQ1NjM2|base64 -d |xxd -r -p|xortool-xor -s 'LwKSukajw' -f -
INTIGRITI{4ndr01d_x0r_m4g1c!!}
```
