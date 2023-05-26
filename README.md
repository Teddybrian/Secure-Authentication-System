# Secure-Authentication-System
Implementation of a secure authentication system using java. 
The system has several options where user can register account, login to existing account, reset password for existing account and loging out. Credentials are secured by SHA-256 which is added up by salt algorithm to ensure total security agains Cross Site-Scripting and SQL injection. 
When resgister is selected, user is prompted to add user name and a password. the user can then progress to login using credentials created. 
In case user wants to reset password, they have to request for a reset code which is provided after they enter their user name. The reset password is used to make changes to the password. 
If User wants to logout, the system generates a session code that is used by users to exit the system
