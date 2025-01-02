1. Find LFI via html injection in spotify code on `/profile`. Triggers when a profile card is generated ("Generate profile card" `profile/generate-profile-card`)
2. Initial exploration:
    1. Get idea of file structure by checking path: `<script>document.body.append(location.href)</script>`
    2. Check common files such as `index.js` and `app.js` (which is the right one in this case): `<iframe src="/opt/app/app.js" style="width: 999px; height: 999px"></iframe>`
    3. Explore routes: `<iframe src="/opt/app/routes/index.js" style="width: 999px; height: 999px"></iframe>`
3. Notice the `/admin` endpoint.
4. Check the `isAdmin` middleware: `<iframe src="/opt/app/middleware/check_admin.js" style="width: 999px; height: 999px"></iframe>`
5. Notice that the `catch` statement does not stop execution and that causing an error when parsing the `userData` object as JSON would skip the admin check.
6. Explore the user service to get an understanding of how users are stored: `<iframe src="/opt/app/services/user.js" style="width: 999px; height: 999px"></iframe>`
7. Notice users are stored as JSON files in the `data` folder.
8. In the `routes/index.js` file, notice the `userOptions` POST parameter.
9. Check the `generateProfileCard.js` file to see how it's used and how the profile card is generated: `<iframe src="/opt/app/utils/generateProfileCard.js" style="width: 999px; height: 999px"></iframe>`
10. Notice that the parameter is passed as options for the puppeteer `pdf` function.
11. After some research, discover the `path` parameter: https://pptr.dev/api/puppeteer.pdfoptions
12. Notice that the `path` parameter can be used to save the PDF in a specified location
13. Use the `path` parameter to overwrite your user's data object in the `data` folder with the contents of the PDF (which is invalid JSON)
14. Go to `/admin` to get the flag

[FULL WRITEUP and VIDEO](https://book.cryptocat.me/ctf-writeups/2023/intigriti/web/my_music)
