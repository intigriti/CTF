[COMMUNITY WRITEUP](https://berliangabriel.github.io/post/1337up-ctf-2023/)

#### solve.sage

```py
from out import cs, s

vrs = [var(f'x_{i}') for i in range(10)]
equation = sum(c*v for c, v in zip(cs, vrs)) - s
coeffs = equation.polynomial(ZZ).coefficients()
M = Matrix(coeffs).transpose()
M = M.augment(identity_matrix(M.nrows()))
M[-1, -1] = 0
M = M.LLL()
flag = ""
for i in M[0][1:-1]:
    flag += chr(i % 1000)
print("INTIGRITI{%s}" % flag)
```
