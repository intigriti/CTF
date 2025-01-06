#### solve.py

```py
val = []
flag = "1337UP{b4s1c_sh1f7_n0_b1n0m1al}"
flag_length = 9

def factorial(n):
    f = 1
    for i in range(2, n+1):
        f *= i
    return f

def series(A, X, n):
    nFact = factorial(n)
    for i in range(0, n + 1):
        niFact = factorial(n - i)
        iFact = factorial(i)
        aPow = pow(A, n - i)
        xPow = pow(X, i)
        val.append(int((nFact * aPow * xPow) / (niFact * iFact)))


A = 1; X = 1; n = 26
series(A, X, n)
print(val)

ct = []
for i in range(len(flag)):
    ct.append(chr(ord(flag[i])+val[i]%26))

print(ct)

pt = []
for i in range(flag_length):
    pt.append(chr(ord(ct[i])-val[i]%26))

print(pt)
```
