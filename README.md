# Cyberhawk-Intelligence

# Introduction
Cyberhawk Intelligence is a threat intelligence system that utilizes the VirusTotal API for various functionalities, including file scanning, URL scanning, and domain search. It features role-based login for regular users and admins. Additional functionalities include command execution, CWE fetching, report writing, and submission. User management is handled through MySQL storage, while reports are stored and submitted via Firestore.

## Regular User Dashboard
### CLI
Offers an interface for executing Windows-based commands.

### Fetch CWEs
Enables retrieval and display of CWEs.

### Browse
Enables file upload to the system from the file explorer.

### Scan File
Utilizes the VirusTotal API to scan uploaded files for any presence of malware and outputs the scan results.

### Scan URL
Utilizes the VirusTotal API to scan URLs for malicious components.

### Search
Utilizes the VirusTotal API to perform a search on a specific domain provided by a user and displays detailed information about the domain.

### Reporting
An interface within the system that allows a logged-in user to type and store reports in Firestore.

## Admin Dashboard
### View Users
Allows an admin to view users present on the system.

### Delete User
Allows an admin to delete a user of choice from the system.

### Add User
Allows an admin to add a user into the system.

### Retrieve
Allows an admin to retrieve reports from Firestore and view the report contents.

### Save
Allows local saving of report files retrieved by the admin on local storage.

# User Management
MySQL database is used to store all users on the system based on their role, i.e., "admin" or "user". Passwords stored in the MySQL database are hashed to enhance security.

