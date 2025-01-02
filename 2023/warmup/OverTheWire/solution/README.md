# Part 1

[FULL VIDEO WALKTHROUGH](https://youtu.be/CsyQFzTJ09w?t=112)

1. Extract the flag.zip from PCAP (wireshark, tshark etc)
2. Find the note advising the recipient to use their FTP password, with a "small update" - this is a hint regarding the year, i.e. the password should be "5up3r_53cur3_p455w0rd_2023" rather than the "5up3r_53cur3_p455w0rd_2022" used to login to the FTP server
3. Unzip the flag with password

# Part 2

[FULL VIDEO WALKTHROUGH](https://youtu.be/CsyQFzTJ09w?t=317)

1. Extract image using wireshark, first is just a test using exifdata
2. Second image uses LSB stego and can be cracked with zsteg
