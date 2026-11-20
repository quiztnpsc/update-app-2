Revision Quiz app  (version 2026.11.16)

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
