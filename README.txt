Revision Quiz app  (version 2026.11.17)

TWO ADMINS
config.js lists the approved admin emails (only these can log in on the Admin tab):
  admins:["aishusk2006@gmail.com","bsmanojprabaharan2001@gmail.com"]
Each admin sets their OWN password the first time they log in (Admin tab). To change who can be admin, edit config.js on GitHub
(pencil icon), then Commit. The old single admin account in the database is no longer used (this is the "reset").

DATABASE
config.js also holds your Firebase Realtime Database link (rtdb). Firebase rules: see firebase_rules.json.

UPLOAD
GitHub > Add file > Upload files > drag EVERYTHING (including the data and sheets folders) > Commit changes.
Do not upload content.json if you have added your own notes / live classes.

NOTE: students who signed up before may show "-" for mobile/email (their details were protected with the old admin key).
New sign-ups are readable by both admins.

RECOVERING DETAILS OF STUDENTS WHO SIGNED UP BEFORE THE TWO-ADMIN UPDATE
After uploading this version, log in as an approved admin (Admin tab). If some students show locked details, a card
"Recover old student details" appears in the Admin page. Enter the password of the person who FIRST logged in as admin
on this app before the update. Details are then unlocked for both admins.
IMPORTANT: before recovering, do NOT delete the 'admin' row or the 'adminkeys' rows in Firebase.
