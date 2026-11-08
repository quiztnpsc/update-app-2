Revision Quiz app  (version 2026.11.12)

FIRST TIME (one-time)
1. Upload ALL files in this folder to your web host (replace the old files).
2. Open the app, close it, and open it again once.

HOW TO PUSH A FEATURE UPDATE (students do NOT reinstall)
1. Upload only the new app.js (and index.html if it is included) to the same place on your host.
2. Edit version.json: change "v" to a new number (e.g. 2026.12.01) and write a short "notes" message.
   data.js (the big quiz images file) does NOT need to be uploaded again unless the quizzes change.
3. Students see a banner "New version available" and tap "Update now" (or the "Check for updates" button).
   Their logins, answers and scores are kept. Only the small files are downloaded.

SIGN-UP
Students create their own account on the login screen (first name, last name, mobile, email, password).
Their details are encrypted and only the admin can read them. The admin must log in once first to open sign-up.

FORGOT-PASSWORD EMAIL OTP
EmailJS is already built in (Service service_ixah061, Template template_qu8z0gi). The OTP is emailed automatically.
Requirements: the Gmail service must be connected in your EmailJS dashboard, and the template must use {{email}}, {{passcode}} and {{time}}.
Works on your GitHub Pages / hosted link, not inside the claude.ai link. OTP valid for 15 minutes.

Note: this installed copy stores users/scores on each device. For one shared class list across all devices, use the web link.
