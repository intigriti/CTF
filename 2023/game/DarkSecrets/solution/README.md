[FULL WRITEUP / VIDEO](https://book.cryptocat.me/ctf-writeups/2023/intigriti/gamepwn/dark_secrets)

1. Find rgss2a file with procmon (or some other forensics)
2. Create project with GitHub tool (https://github.com/uuksu/RPGMakerDecrypter) and load it, extract all (and create project)
3. Install RGP Maker VX (RPG Maker VX) to view/modify game
4. When we play game defeate boss, we find the well to jump in and have to enter a code - find this in MAP001 events (39118326)
5. Final boss is unbeatable, we need to update the game
6. Defeat the boss and get flag

Intended playthrough: - show around map (remember space to interact) - note there is a well (blocked by wood) - we go in and defeat the boss - now the well is cleared! - we go inside and talk to the man, next we can save (you'll see why) - enter the pass (incorrectly), then we show how to identify the game file type, how to decrypt, how to view etc - now we know we can enter the correct key: 39118326 - we fight the demonlord and die instantly, therefore let's go and edit the demonlord! - now we patch boss to be weak (also set key to 0000000 to save time) - move the game binary from temp with the patched files and load game - defeat the final boss, flag is printed in b64 - flag will be truncated, in this case need to check script editor for full value (ctrl + F)
