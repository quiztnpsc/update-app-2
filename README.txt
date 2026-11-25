Vettri Namadhey app  (version 2026.11.23)

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

LOCKED STUDENT DETAILS - WHAT THE ADMIN PAGE TELLS YOU
- "Ask the other admin": the student signed up while only the other admin had logged in. The other admin opens the Admin page once; then refresh.
- "Signed up before the two-admin update": enter the first admin's old password to unlock. If that does not work, the old key was replaced
  and the details cannot be recovered. Use "Remove these students" so they can sign up again (their scores are removed too).

NEW IN 2026.11.20
1. TEST SCHEDULE: Admin page > "Schedule tests": set when each test opens and closes (date + time). Outside that time students cannot
   start it; a test in progress submits itself at the closing time. Leave a time empty for no limit on that side. Admins are never locked out.
2. NOTES UPLOAD: Admin page > Add a note > attach a PDF / image / document (up to 4 MB). Needs the Firebase database.
   IMPORTANT: in Firebase > Realtime Database > Rules, paste the contents of firebase_rules.json again (it adds "files") and Publish.
3. New app logo (peacock and golden pen).

NEW IN 2026.11.21 - ADMIN CAN SEE WHICH OPTION EACH STUDENT MARKED
Admin page > "Check a student's answers" (choose student + test), or the "👁 Answers" button in a student's score cell.
Shows every question with the student's marked option, the correct option, Correct / Wrong / Not answered, filters, and
whether the test is submitted or still in progress. Works for all built-in tests and for quizzes you created.
Needs the Firebase database (answers are saved there a few seconds after each click). No new Firebase rules are needed.

NEW IN 2026.11.22: the app is now called "Vettri Namadhey" with the new peacock-and-rooster logo. Icons: logo-192.png, logo-512.png, logo-maskable-512.png, apple-touch-icon.png.
If phones still show the old icon/name, remove the app from the home screen and add it again (phones cache the icon).
The old icon-192.png / icon-512.png files are no longer used; you may delete them from GitHub.

NEW IN 2026.11.23 - ADMIN APPROVES NEW STUDENTS
A student who signs up is told "Please wait for the admin to approve it" and cannot login yet.
The admin sees a "🔔 Admin (N new)" button and, inside the Admin page, a card "New students waiting for approval"
with Approve / Reject / Approve all. After approval the student can login (then give them test access as usual).
Students who signed up before this update are treated as already approved.
