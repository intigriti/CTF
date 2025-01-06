## Crypto - Dante's Inferno

### Methodology

-   1 : `change header of zip file`
-   2 : `Run the text/prgm in Malboge decoder`
-   3 : `RSA cube root attack`
-   4 : `Submit the flag`

### Header change

-   change the header to `50 4B 03 04` ( I've used hexedit )
-   Refernce - `https://bitvijays.github.io/LFC-Forensics.html`

![image](https://user-images.githubusercontent.com/56447720/151650176-7bba0deb-ce45-442c-811d-72ceebfc913f.png)

-   After unzipping we had a file which had encoded ciphertext

### Malboge decoder

-   The text file and challenge name had reference of Malboge language
-   Reference - https://malbolge.doleczek.pl/
-   This was the ciphertext

```
D'`r_"\!65|{8yTBu-,P0<L']m7)iE3ffT"b~=+<)([wvo5Vlqping-kjihgfH%cb[`Y}@VUyxXQPUTMLpPOHMFj-,HGF?>bBA:?>7[;:9870v.3,PO/.'K%*)"F&%ed"y~w=uzsr8potml21oQmf,diha`e^$\aZ_^W{[=<XWPOs65KPIHGFjJIHG@?c=B;@?>7[;4981U5.R21q)M-&%I#('~D${"y?wv{t:9qYun4rkSonmlkdihg`&d]\aZY}@V[ZYXQuU76LKo2HGFjiCHA@?c=B;@?>7[;4981UT4321q)M'&%$)"!E%e{z@~}_uzs9wvotsrk1onPle+*)a`e^$\aZY}W\[TSwvVUTMLpPIHGLEiIHG@(>baA:^!~<;:921U54t2+*N.'&%*)"FEfe{"y?>v{zsxqp6nVl2pohg-ejib('_^]b[Z~^@?UZSRvPONr54JImGLKDIBfe(>=<`#">=65Y987w/43,P0)o-,+$H('&%|B"!~w|{t:xZpo5Vlqjinmled*Ka`edc\"Z_^]Vz=YXQPtN6LKoO10FKDhHAF?cCBA#"8\65Y987w/43,P*p.-&J*#i'&}C#"!x>|{zyr8ponmrqj0/mfNjibg`_^$b[Z_X]VUySRQPUNr54JImMLEDhHA@dD=B;:^8=6;4X2Vwv4-,+*N(-,%$H(!&}C#"!xwv<zyxZpo5Vrkjongf,jibJ`_^$\aZ_^]VzTYRWVOsSRQJn1MFKJCBf)(>=<`#"8\654XW165.-Q10)('K+$#G'&fe#"y?}vuzyxq7utsrkj0hgfkjihg`_^$\[ZY}|V[ZSRWPtT6LKJIm0/KDIHAeEDC<;:9]\6Z4z816/4-,P0/.'&%$H('&%ed"y~w={tsr8vo5mlqponmf,diba`ed]#"Z_X]V[TxRQVONMLp3INGFEi,HAF?c=<;@9876Z{921U/432+O)o'&%I#(!&%${A@~}|{ts9qpun4lkpi/glkdcba'_dcbaZY}]\UyS;QVUNrq4JIHMFj-,BGF?cCBA#"8=6Z:98705.-Q1*p.-&JI#"!~}C{"!~}v<tsrqp6Wsl2jinmlkdcba'e^cb[Z~^@?UZSRv98TSLKo2NMFEJIBf)EDC<;_98=6;4X2765.-Q10)o'&%I#i'&}C{"y~w=utyrqp6tsrqSi/g-ediha'eG]#[ZY}@VzTYXWVOs6LKo2NMFKJCBf@ED=a;@9]=<54XW765.-Q1q)ML,%*)"!~}C{"yx}v<;yrwvo5slqpohg-kdchgf_%]\[Z~}@VzZYRWVOsSRQJnN0/EDCg*)E>b<;@?8=6Z:9810T4t2+*N(-,%$H('gf|Bz!x}|u;srqpon4lTjohg-kjiba'e^c\"!Y^]\[TxXW9ONMLpPOHMFjDIHA@E>b<;:9]=6;492V65.R2+*N.'&+*#G'~%|#"yx>=uzsxwvun43kjohgf,jihgfe^$\[Z_^W{[TYXWVOsSRQJONMLEiCHG@?cb%;@?8\6;492VUTu-2+ONon,+*#G!&}C#"!x>|u;yrwpun4lTjohg-eMib(fe^cb[!Y^]\Uy<;WVONSLpJIHMFKDhU
```

-   Decoded text

```
ct =  873155658033286165345893055075219953448439133304998599826332294122364399613515391492517530741997313686269671365469457117326837553092248386584401016236110628510070270063568461732767950347057143066788600143225698168693961311821925168117751654884111332051719013

```

### RSA Solve.py

-   The description had an hint of `cube root` attack

```py
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

ct = ct =  873155658033286165345893055075219953448439133304998599826332294122364399613515391492517530741997313686269671365469457117326837553092248386584401016236110628510070270063568461732767950347057143066788600143225698168693961311821925168117751654884111332051719013
flag = iroot(ct,3)

flag = long_to_bytes(flag[0]).decode()
#print(flag)
```

### Flag

```
1337UP{U_d3CrYPt3D_th3_k3Y_30494762}
```
