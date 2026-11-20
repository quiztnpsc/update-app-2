Revision Quiz app  (version 2026.11.15)

THE FIX: students on other phones could not sign up ("registration not open").
Reason: without a shared database every phone has its own separate data. This version connects to a free Firebase
Realtime Database so ALL phones share users, scores, access, notes and live classes.

STEPS (once)
1. console.firebase.google.com > Add project (any name, turn Google Analytics off).
2. Build > Realtime Database > Create Database > choose Singapore > "Start in locked mode" > Enable.
3. Open the "Rules" tab, delete everything, paste the contents of firebase_rules.json, click Publish.
4. Open the "Data" tab and copy the database link at the top (looks like https://NAME-default-rtdb.asia-southeast1.firebasedatabase.app).
5. (Already done for you: config.js contains your database link.)
6. Upload all other files of this folder to GitHub (Add file > Upload files), Commit.
7. Open the app, log in as ADMIN first (this turns on sign-up), then students can sign up from any phone.

NOTE: students who signed up earlier on their own phones must sign up again (their old accounts were only on that phone).
