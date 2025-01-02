# Over The Edge

-   Diffucuilty : Easy
-   Category : Pwn

# Writeup

-   Looking at the source code we can see this is accepting a number and adds 65 to it and checks if that value is equals to `1337` when substracted from 0.

```python
    num1[0] = (a + 65)
    if (num2[0] - num1[0]) == 1337:
        return 'You won!'
```

-   Naturally when any value is subtracted from 0, should be a negative value. So if we provide a negative value as out number, we would get the substraction of a negative value which is the addition of a positive value.
-   But here it prevents us from provding any negative values. So we need to find another way.

```python
    if a < 0:
        return "Exiting..."
```

-   If you look at the declarations of the variables, `num1` and `num2`, you can see they are of type `unint64` which is used to declare `64 bit unsigned integers` in python

```python
    num1 = np.array([0], dtype=np.uint64)
    num2 = np.array([0], dtype=np.uint64)
```

-   These `64 bit unsigned integers` have a range from `0 to 18446744073709551615`

```
    np.uint8: 8-bit unsigned integer (0 to 255)
    np.uint16: 16-bit unsigned integer (0 to 65535)
    np.uint32: 32-bit unsigned integer (0 to 4294967295)
    np.uint64: 64-bit unsigned integer (0 to 18446744073709551615)
```

-   So if we were to substract 65 from the largest `uint64` (`18446744073709551615`), then when another 65 added and substracted from 0, this would result in a positive 1
-   But since we need `1337`, instead of 65, we should substract another 1336 from it.

```python
>>> 18446744073709551615 - 65 - 1336
18446744073709550214
>>>

```

```bash
Time to jump over the edge!
18446744073709550214
FLAG{fUn_w1th_1nt3g3r_0v3rfl0w_11}
```
