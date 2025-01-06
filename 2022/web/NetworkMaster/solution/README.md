1. Apply for an account using the payload `\` as the first name and `) UNION SELECT password,2,3,4,5,6,7 FROM admins #` as the last name and some random email and password
2. Note down the `id` from the request response
3. Send a GET request to `/api/user/findUsersWithSameName` using the value from step 2 in a cookie named `userId`. (`Cookie: userId=<your_id>`)
4. Notice you got the flag in the response
