import bcrypt
import tkinter as tk
from tkinter import messagebox,PhotoImage,scrolledtext,filedialog
from tkinter import  ttk
import subprocess
import MySQLdb
from configparser import ConfigParser
import requests
import json
from bcrypt import hashpw,gensalt,checkpw
import itertools
import firebase_admin
from firebase_admin import credentials, firestore
from bs4 import BeautifulSoup

#initialize firestore
cred = credentials.Certificate('/path to your json')
firebase_admin.initialize_app(cred)

db = firestore.client()

# Read configuration from the config.ini file
config = ConfigParser()
config.read('config.ini')

db_host = config.get('database', 'host')
db_user = config.get('database', 'user')
db_password = config.get('database', 'password')
db_name = config.get('database', 'database')



def validate_login():
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    # validate user login
    try:
        # Connect to MySQL database
        connection = MySQLdb.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor()

        # Check if the entered username exists and the password is correct
        # use you sql table name in this case i have a table mysystemusers
        query = "SELECT password FROM mysystemusers WHERE username = %s"
        cursor.execute(query, (entered_username,))
        result = cursor.fetchone()

        if result:
            stored_password = result[0]
            if checkpw(entered_password.encode('utf-8'), stored_password.encode('utf-8')):

                dashboard_window = tk.Toplevel(root)
                dashboard_window.geometry('1360x723')
                dashboard_window.configure(bg='black')
                dashboard_window.title('dashboard window')

                dashbackground_image = PhotoImage(file='updateduserdash.png')
                dashbackground_label = tk.Label(dashboard_window, image=dashbackground_image, bd=0)
                background_label.photo = dashbackground_image
                dashbackground_label.place(x=0, y=0, relwidth=1, relheight=1)


                #fetch vulnerabilities

                def fetch_vulnerabilities():
                    try:
                        # Endpoint URL for fetching weakness types (CWEs)
                        url = 'https://nvd.nist.gov/vuln/categories'

                        response = requests.get(url)
                        response.raise_for_status()  # Raise an exception for HTTP errors

                        # Parse HTML content
                        soup = BeautifulSoup(response.content, 'html.parser')

                        # Extract CWEs
                        cwe_list = []
                        for row in soup.find_all('tr')[1:]:  # Skip header row
                            cells = row.find_all('td')
                            cwe_id = cells[0].text.strip()
                            cwe_name = cells[1].text.strip()
                            cwe_description = cells[2].text.strip()  # Extract description directly from cell
                            cwe_list.append((cwe_id, cwe_name, cwe_description))

                        # Create a new window to display the CWEs
                        result_window = tk.Toplevel(dashboard_window)
                        result_window.title("Weakness Types (CWEs)")
                        result_window.configure(bg='black')

                        # Create a Treeview widget
                        tree = ttk.Treeview(result_window, columns=("CWE ID", "Name", "Description"), show="headings")
                        tree.pack(fill="both", expand=True)

                        # Set column headings
                        tree.heading("CWE ID", text="CWE ID")
                        tree.heading("Name", text="Name")
                        tree.heading("Description", text="Description")

                        # Add horizontal scrollbar
                        h_scrollbar = ttk.Scrollbar(result_window, orient="horizontal", command=tree.xview)
                        h_scrollbar.pack(side="bottom", fill="x")
                        tree.configure(xscrollcommand=h_scrollbar.set)

                        # Insert CWEs into the Treeview
                        for cwe in cwe_list:
                            tree.insert("", "end", values=cwe)

                    except requests.RequestException as e:
                        # Display error message if a request exception occurs
                        error_window = tk.Toplevel(dashboard_window)
                        error_window.title("Error")

                        error_text = tk.Text(error_window, width=80, height=5)
                        error_text.pack(padx=10, pady=10)

                        error_text.insert(tk.END, 'Request Error: ' + str(e))

                    except Exception as e:
                        # Display error message if any other exception occurs
                        error_window = tk.Toplevel(dashboard_window)
                        error_window.title("Error")

                        error_text = tk.Text(error_window, width=80, height=5)
                        error_text.pack(padx=10, pady=10)

                        error_text.insert(tk.END, 'Error: ' + str(e))

                # open terminal window in dashboard window
                def open_terminal():
                    def execute_command():
                        # Clear the existing output
                        output_text.delete(1.0, tk.END)
                        command = command_entry.get()
                        try:
                            result = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT)
                        except subprocess.CalledProcessError as e:
                            result = f"Error: {e.output}"

                        # Insert the new result
                        output_text.insert(tk.END, result)

                        # Clear the input field
                        command_entry.delete(0, tk.END)

                    # Create the terminal window
                    terminal_window = tk.Toplevel(dashboard_window)
                    terminal_window.title("Tkinter CLI")
                    terminal_window.configure(bg='black')
                    terminal_window.resizable(False, False)

                    # Command Entry
                    command_entry_label = tk.Label(terminal_window, text="Enter 🦅 command:", bg='black', fg='white',
                                                   font=('helivitica'
                                                         , 12,'bold'))
                    command_entry_label.pack(pady=5)

                    command_entry = tk.Entry(terminal_window, width=50, font=('helivitica', 12), bg='light grey')
                    command_entry.pack(pady=5)

                    # Execute Button
                    execute_button = tk.Button(terminal_window, text="Execute", bg='red', relief=tk.RAISED,
                                               activeforeground='white',
                                               fg='white', activebackground='red', command=execute_command,
                                               cursor='hand2'
                                               , font=('helivitica', 12, 'bold'))
                    execute_button.pack(pady=5)

                    # Output Text
                    output_text = scrolledtext.ScrolledText(terminal_window, wrap=tk.WORD, width=60, height=15,
                                                            bg='black', fg='white')
                    output_text.pack(pady=10)

                    terminal_window.mainloop()

                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)

                # CLI button
                terminal_button = tk.Button(dashboard_window, text='🦅 CLI', bg='dark red', fg='white',
                                            command=open_terminal,
                                            font=('helivitica', 12, 'bold'), activebackground='dark red',
                                            activeforeground='white')
                terminal_button.place( x=10, y=80,width=100)

                # fetch CWEs button
                fetch_button = tk.Button(dashboard_window, text="Fetch CWEs",bg='dark red', fg='white',
                                            command=fetch_vulnerabilities,
                                            font=('helivitica', 12, 'bold'), activebackground='dark red',
                                            activeforeground='white')
                fetch_button.place(x=10,y=130)


                # open file explorer
                def browse_file():
                    file_path = filedialog.askopenfilename(parent=dashboard_window)
                    file_var.set(file_path)



                # get detection

                def get_detection_results(api_key, resource):
                    url_report = 'https://www.virustotal.com/vtapi/v2/file/report'
                    params = {'apikey': api_key, 'resource': resource}
                    response_report = requests.get(url_report, params=params)

                    if response_report.status_code == 200:
                        report = response_report.json()
                        detection_results = report.get('scans', {})
                        return detection_results
                    else:
                        print(f"Error getting detection results. Status code: {response_report.status_code}")
                        return {}

                # scan file
                def scan_file():
                    file_path = file_var.get()
                    if not file_path:
                        return


                    api_key = 'provide your virus total api key'
                    url_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
                    url_report = 'https://www.virustotal.com/vtapi/v2/file/report'

                    with open(file_path, 'rb') as file:
                        files = {'file': (file.name, file)}

                        params = {'apikey': api_key}
                        response_scan = requests.post(url_scan, files=files, params=params)

                        if response_scan.status_code == 200:
                            scan_results = response_scan.json()
                            resource = scan_results.get('resource')

                            # Check if the scan was successful
                            if resource:
                                detection_results = get_detection_results(api_key, resource)

                                result_window = tk.Toplevel(root)
                                result_window.title("Scan Result")
                                result_window.configure(bg='black')
                                result_window.geometry('600x380')
                                result_window.resizable(False,False)

                                result_text = tk.Text(result_window, wrap="none", height=20, width=70,fg='white',bg='black')
                                result_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
                                # vertical scroll bar
                                scrollbar = ttk.Scrollbar(result_window, command=result_text.yview)
                                scrollbar.grid(row=0, column=1, pady=10, sticky="ns")
                                result_text['yscrollcommand'] = scrollbar.set
                                #horizontal scroll bar
                                horizontalscrollbar = ttk.Scrollbar(result_window, command=result_text.xview, orient="horizontal")
                                horizontalscrollbar.grid(row=1, column=0, padx=10, sticky="ew")
                                result_text['xscrollcommand'] = horizontalscrollbar.set


                                # Display scan results
                                result_text.insert(tk.END, "Scan Results:\n")
                                for key, value in scan_results.items():
                                    result_text.insert(tk.END, f"{key}: {value}\n")

                                # Display detection results
                                result_text.insert(tk.END, "\nDetection Results:\n")
                                for key, value in detection_results.items():
                                    if value:  # Check if the result is true
                                        # Highlight the detected keyword in red
                                        result_text.tag_configure("green", foreground="green",font=('helvetica',12,'bold'))
                                        result_text.insert(tk.END, f"{key}: ", "green")
                                        result_text.insert(tk.END, f"{value}\n")

                                    else:
                                        result_text.insert(tk.END, f"{key}: {value}\n")


                        else:
                            print(f"Error scanning file. Status code: {response_scan.status_code}")

                # scan url
                def scan_url():
                    url_to_scan = url_var.get()
                    if not url_to_scan:
                        return

                    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
                    api_key = 'provide your virus total api key'
                    url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'

                    params = {'apikey': api_key, 'url': url_to_scan}
                    response_scan = requests.post(url_scan, params=params)

                    if response_scan.status_code == 403:
                        print("Error: Access Forbidden. Check your API key and permissions.")
                        return

                    if response_scan.status_code == 200:
                        try:
                            scan_results = response_scan.json()
                        except json.JSONDecodeError as e:
                            print(f"Error decoding JSON: {e}")
                            return

                        result_window = tk.Toplevel(root)
                        result_window.title("URL Scan Result")
                        result_window.config(bg='black')

                        result_text = tk.Text(result_window, wrap="none", height=10, width=50,bg='black',fg='white')
                        result_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

                        scrollbar = ttk.Scrollbar(result_window, command=result_text.yview)
                        scrollbar.grid(row=0, column=1, pady=10, sticky="ns")
                        result_text['yscrollcommand'] = scrollbar.set

                        # Display URL scan results
                        result_text.insert(tk.END, "URL Scan Results:\n")
                        for key, value in scan_results.items():
                            result_text.insert(tk.END, f"{key}: {value}\n")

                        result_text.config(state=tk.DISABLED)  # Make the text widget read-only
                    else:
                        print(f"Error scanning URL. Status code: {response_scan.status_code}")



                 # search for domains

                def search_vt():
                    query = search_var.get()
                    if not query:
                        return

                    # Replace 'YOUR_API_KEY' with your actual VirusTotal API key
                    api_key = 'provide your virus total api key'
                    url_search = 'https://www.virustotal.com/vtapi/v2/domain/report'

                    params = {'apikey': api_key, 'domain': query}
                    response_search = requests.get(url_search, params=params)

                    if response_search.status_code == 403:
                        print("Error: Access Forbidden. Check your API key and permissions.")
                        return

                    if response_search.status_code == 200:
                        try:
                            search_results = response_search.json()
                        except json.JSONDecodeError as e:
                            print(f"Error decoding JSON: {e}")
                            return

                        result_window = tk.Toplevel(root)
                        result_window.title(" Search Result")
                        result_window.configure(bg='black')
                        result_window.geometry('600x380')
                        result_window.resizable(False,False)

                        result_text = tk.Text(result_window, wrap="none", height=20, width=70,bg='black',fg='white')
                        result_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

                        scrollbar = tk.Scrollbar(result_window, command=result_text.yview)
                        scrollbar.grid(row=0, column=1, pady=10, sticky="ns")
                        result_text['yscrollcommand'] = scrollbar.set

                        xscrollbar = tk.Scrollbar(result_window, orient="horizontal", command=result_text.xview)
                        xscrollbar.grid(row=1, column=0, pady=10, sticky="ew")
                        result_text['xscrollcommand'] = xscrollbar.set

                        # Display search results
                        result_text.insert(tk.END, " Search Results:\n")
                        for key, value in search_results.items():
                            result_text.insert(tk.END, f"{key}: {value}\n",'green')

                        # Display vendor analysis details
                        detected_urls = search_results.get('detected_urls', [])
                        if detected_urls:
                            result_text.insert(tk.END, "\nVendor Analysis Details:\n")
                            for entry in detected_urls:
                                vendor = entry.get('scan_engine')
                                analysis = entry.get('result')
                                result_text.insert(tk.END, f"Vendor: {vendor}, Analysis: {analysis}\n")

                        result_text.config(state=tk.DISABLED)  # Make the text widget read-only
                    else:
                        print(f"Error searching in VirusTotal. Status code: {response_search.status_code}")

                # functions to enable report submission
                def submit_report(report_text, file_name):
                    try:
                        # Add the report to the 'reports' collection in Firebase
                        db.collection('reports').add({file_name: report_text})
                        messagebox.showinfo('Success', 'Report submitted successfully!',parent=dashboard_window)

                    except Exception as e:
                        messagebox.showerror('Error', f'Error submitting report: {e}')

                def on_submit_button():
                    report_text = report_entry.get("1.0", "end-1c")  # Get the report text from the Text widget
                    file_name = file_name_entry.get()  # Get the file name from the Entry widget

                    if report_text.strip() and file_name.strip():
                        submit_report(report_text, file_name)
                        report_entry.delete("1.0", tk.END)  # Clear the Text widget
                        file_name_entry.delete(0, tk.END)  # Clear the Entry widget
                    else:
                        messagebox.showwarning('Warning',
                                               'Please enter both a report and a file name before submitting.'
                                               ,parent=dashboard_window)


                # scanner widgets
                file_label = tk.Label(dashboard_window,text='File',bg='#00004d',fg='red',font=('helvetica',14,'bold'))
                file_label.place(x=500,y=80)
                file_var = tk.StringVar()
                file_entry = tk.Entry(dashboard_window, textvariable=file_var, state="readonly",highlightcolor='red',font=('helvitica',12,'bold')
                                        ,highlightthickness=3,bg='black',fg='black',insertbackground='white')
                file_entry.place(x=590,y=80,width=250,height=28)

                # browse file button
                browse_button = tk.Button(dashboard_window, text="Browse",relief=tk.RAISED,background='blue',cursor='hand2',
                                font=('helvitica',10,'bold')   ,fg='white',activebackground='blue',activeforeground='white'
                                          ,command=browse_file)
                browse_button.place(x= 880,y=80,width=100)
                # scan button
                scan_button = tk.Button(dashboard_window, text="Scan File", relief=tk.RAISED,background='blue',cursor='hand2',
                                font=('helvitica',10,'bold'),command=scan_file,fg='white',activebackground='blue',activeforeground='white')
                scan_button.place(x=990,y=80,width=100)

                # url scan section
                url_label = tk.Label(dashboard_window, text="URL:",bg='#00004d',fg='red',font=('helvetica',14,'bold'))
                url_label.place(x=500,y=120)
                url_var = tk.StringVar()
                url_entry = tk.Entry(dashboard_window, textvariable=url_var,highlightcolor='red',font=('helvitica',12,'bold')
                                        ,highlightthickness=3,bg='#00004d',fg='white',insertbackground='white')
                url_entry.place(x=590,y=120,width=250,height=28)

                url_scan_button = tk.Button(dashboard_window, text="Scan URL",relief=tk.RAISED,background='blue',cursor='hand2',
                                font=('helvitica',10,'bold'),command=scan_url,fg='white',activebackground='blue',activeforeground='white')
                url_scan_button.place(x=880,y=120,width=100)

                # search section
                search_label = tk.Label(dashboard_window, text="Search:",bg='#00004d',fg='red',font=('helvetica',14,'bold'))
                search_label.place(x=500,y=160)

                search_var = tk.StringVar()
                search_entry = tk.Entry(dashboard_window, textvariable=search_var,highlightcolor='red',font=('helvitica',12,'bold')
                                        ,highlightthickness=3,bg='#00004d',fg='white',insertbackground='white')
                search_entry.place(x=590,y=160,width=250,height=28)

                search_button = tk.Button(dashboard_window, text="Search ",relief=tk.RAISED,background='blue',cursor='hand2',
                                font=('helvitica',10,'bold')   ,fg='white',activebackground='blue',activeforeground='white',command=search_vt)
                search_button.place(x=880,y=160,width=100)

                # widgets for reporting section
                report_entry = tk.Text(dashboard_window, wrap=tk.WORD,insertbackground='white',highlightcolor='red',
                                highlightthickness=3      , height=20, width=80,bg='black',fg='white')
                report_entry.place(x=400,y=250)

                vertical_scrollbar = tk.Scrollbar(dashboard_window, command=report_entry.yview)
                vertical_scrollbar.place(x=1044.7, y=250, height=326)
                report_entry['yscrollcommand'] = vertical_scrollbar.set

                # Create an Entry widget for file name input
                file_name_entry = tk.Entry(dashboard_window,highlightcolor='red',font=('helvitica',12,'bold')
                                        ,highlightthickness=3,bg='#00004d',fg='white',insertbackground='white')
                file_name_entry.place(x=400,y=590,width=250)
                file_name_entry.insert(0, 'enter file name')  # Default file name

                # Create a button to submit the report
                submit_button = tk.Button(dashboard_window, text="Submit Report",relief=tk.RAISED,background='dark red',cursor='hand2',
                                font=('helvitica',10,'bold')   ,fg='white',activebackground='dark red',activeforeground='white',command=on_submit_button)
                submit_button.place(x=680,y=590)

                dashboard_window.mainloop()

                # messagebox.showinfo("Success", "Login successful!")
            else:
                messagebox.showerror("Error", "Invalid password.")
        else:
            messagebox.showerror("Error", "User not found.")

    except MySQLdb.Error as err:
        messagebox.showerror("Error", f"Database error: {err}")

    finally:
        if connection:
            cursor.close()
            connection.close()

# create account window
def create_account_window():
    create_account_window = tk.Toplevel(root)
    create_account_window.title("Create Account")
    create_account_window.geometry('400x200')
    create_account_window.configure(bg='dark blue')
    create_account_window.resizable(False,False)

    # Create labels and entry fields
    username_label = ttk.Label(create_account_window, text="Username:",background='dark blue',foreground='white',font=('helevitica'
                                                                                ,12,'bold'))
    username_entry = tk.Entry(create_account_window,font=('helivitica',12),fg='red',bg='light grey')

    password_label = tk.Label(create_account_window, text="Password:",background='dark blue',foreground='white',font=('helevitica'
                                                                                ,12,'bold'))
    password_entry = tk.Entry(create_account_window, show="*",font=('helivitica',12),bg='light grey')


    # Create function for handling account creation
    def create_account():
        username = username_entry.get()
        password = password_entry.get()


        #account creation/validation logic here
        try:
            connection = MySQLdb.connect(
                host=db_host,
                user=db_user,
                password=db_password,
                database=db_name
            )
            cursor = connection.cursor()

            hashed_passwd = hashpw(password.encode('utf-8'),gensalt())

            # Insert new user into the 'mysystemusers' table
            insert_query = "INSERT INTO mysystemusers (username, password,role) VALUES (%s, %s,%s)"
            user_data = (username,hashed_passwd.decode('utf-8'),'user')
            cursor.execute(insert_query, user_data)
            connection.commit()

            messagebox.showinfo("Success", "Account created successfully!")
        except MySQLdb.Error as err:
            messagebox.showerror("Error", f"Error: {err}")

        finally:
            if connection:
                cursor.close()
                connection.close()

        # print(f"Username: {username}, Password: {password}, Confirm Password: {confirm_password}")

        # Close the create account window
        create_account_window.destroy()

    # Create a button to trigger account creation
    create_button = tk.Button(create_account_window, text="Create Account", command=create_account,cursor="hand2"
                               ,bg='red',fg='white',activeforeground='white',activebackground='red',font=(
                                                        'helvetica',10,'bold' ),relief=tk.RAISED,width=15)

    # Grid layout for labels, entry fields, and button
    username_label.grid(row=0, column=0, padx=10, pady=5, sticky="E")
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    password_label.grid(row=1, column=0, padx=10, pady=5, sticky="E")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    # confirm_password_label.grid(row=2, column=0, padx=10, pady=5, sticky="E")
    # confirm_password_entry.grid(row=2, column=1, padx=10, pady=5)
    create_button.grid(row=3, column=1, pady=10)


# admin login window
def open_admin_login_window():

    # validate admin login
    def validate_admin_login():
        username = login_username_entry.get()
        password = login_password_entry.get()

        # Connect to MySQL database
        connection = MySQLdb.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )

        # Create a cursor object
        cursor = connection.cursor()

        # Retrieve user data from the MySQL table
        query = "SELECT username, password, role FROM mysystemusers WHERE username = %s"
        data = (username,)

        cursor.execute(query, data)
        user_data = cursor.fetchone()

        if user_data:
            stored_password = user_data[1]
            role = user_data[2]

            # Verify the password using bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                if role == 'admin':

                    # viewing users in database
                    def view_users():
                        try:
                            connection = MySQLdb.connect(
                                host= db_host,
                                user= db_user,
                                password= db_password,
                                database=db_name
                            )
                            cursor = connection.cursor()

                            # Retrieve usernames of users with the role "user"
                            query = "SELECT username FROM mysystemusers WHERE role = 'user'"
                            cursor.execute(query)
                            result = cursor.fetchall()

                            # Clear previous content in Listbox
                            user_listbox.delete(0, tk.END)

                            # Display the usernames in the Listbox
                            for username in result:
                                user_listbox.insert(tk.END, username[0])

                        except MySQLdb.Error as err:
                            user_listbox.delete(0, tk.END)  # Clear previous content
                            user_listbox.insert(tk.END, f"Error: {err}")

                        finally:
                            if connection:
                                cursor.close()
                                connection.close()

                    # delete user functionality
                    def delete_user():
                        selected_user_index = user_listbox.curselection()

                        if selected_user_index:
                            selected_user = user_listbox.get(selected_user_index)

                            try:
                                connection = MySQLdb.connect(
                                    host= db_host,
                                    user= db_user,
                                    password= db_password,
                                    database= db_name
                                )
                                cursor = connection.cursor()

                                # Delete the selected user from the database
                                delete_query = "DELETE FROM mysystemusers WHERE username = %s"
                                cursor.execute(delete_query, (selected_user,))
                                connection.commit()

                                # Remove the selected user from the Listbox
                                user_listbox.delete(selected_user_index)

                            except MySQLdb.Error as err:
                                print(f"Error deleting user: {err}")

                            finally:
                                if connection:
                                    cursor.close()
                                    connection.close()


                    # admin add user functionality
                    def open_add_user_window():
                        add_user_window = tk.Toplevel(root)
                        add_user_window.title('Add User Window')
                        add_user_window.geometry('300x150')

                        label_username = ttk.Label(add_user_window, text='Username:')
                        label_username.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

                        label_password = ttk.Label(add_user_window, text='Password:')
                        label_password.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

                        entry_username = ttk.Entry(add_user_window)
                        entry_username.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

                        entry_password = ttk.Entry(add_user_window, show='*')
                        entry_password.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

                        def add_user():
                            new_username = entry_username.get()
                            new_password = entry_password.get()

                            # Hash the password using bcrypt
                            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

                            try:
                                connection = MySQLdb.connect(
                                    host= db_host,
                                    user=db_user,
                                    password=db_password,
                                    database=db_name
                                )
                                cursor = connection.cursor()

                                # Insert new user into the database with role 'user' and hashed password
                                insert_query = "INSERT INTO mysystemusers (username, password, role) VALUES (%s, %s, %s)"
                                user_data = (new_username, hashed_password, 'user')
                                cursor.execute(insert_query, user_data)
                                connection.commit()

                                add_user_window.withdraw()

                                messagebox.showinfo("Success", "User added successfully!",parent=admin_dashboard)

                                # Clear entry fields
                                entry_username.delete(0, tk.END)
                                entry_password.delete(0, tk.END)

                            except MySQLdb.Error as err:
                                messagebox.showerror("Error", f"Error: {err}")

                            finally:
                                if connection:
                                    cursor.close()
                                    connection.close()

                        button_add_user = ttk.Button(add_user_window, text='Add User', command=add_user)
                        button_add_user.grid(row=2, column=0, columnspan=2, pady=10)



                    #function to retrieve user report from firebase
                    def retrieve_data():
                        try:
                            # Retrieve data from the 'reports' collection in Firebase
                            reports_ref = db.collection('reports')
                            reports_data = reports_ref.stream()

                            # Display the retrieved data in the Text widget
                            retrieved_data = ""
                            for report in reports_data:
                                report_data = report.to_dict()
                                for field, value in report_data.items():
                                    retrieved_data += f"{field}: {value}\n"
                                retrieved_data += "\n"  # Add a newline between reports

                            # Update the Text widget with retrieved data
                            result_text.config(state=tk.NORMAL)
                            result_text.delete("1.0", tk.END)
                            result_text.insert(tk.END, retrieved_data)
                            result_text.config(state=tk.DISABLED)

                        except Exception as e:
                            messagebox.showerror('Error', f'Error retrieving data: {e}',parent=admin_dashboard)

                    #function to save file on local disk
                    def save_to_file():
                        try:
                            # Get the retrieved data from the Text widget
                            data_to_save = result_text.get("1.0", tk.END)

                            # Ask the user to choose a file location for saving
                            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                                     filetypes=[("Text files", "*.txt")],parent=admin_dashboard)

                            # Save the data to the chosen file
                            with open(file_path, 'w') as file:
                                file.write(data_to_save)

                            messagebox.showinfo('Success', f'Data saved to {file_path}',parent= admin_dashboard)

                        except Exception as e:
                            messagebox.showerror('Error', f'Error saving data: {e}',parent=admin_dashboard)


                    # open admin dashboard
                    admin_dashboard = tk.Toplevel(admin_login_window)
                    admin_dashboard.geometry('1360x723')
                    admin_dashboard.configure(bg='black')

                    # dashboard background image
                    admindashbackground_image = PhotoImage(file='dash_admin.png')
                    admindashbackground_label = tk.Label(admin_dashboard, image=admindashbackground_image, bd=0)
                    admindashbackground_label.photo = admindashbackground_image
                    admindashbackground_label.place(x=0, y=0, relwidth=1, relheight=1)

                    welcome_label = tk.Label(admin_dashboard, text="🦅 WELCOME TO ADMIN DASHBOARD 🦅",
                                             font=("Helvetica", 16, 'bold'),
                                             foreground='red',
                                             background='black')
                    welcome_label.place(x=500, y=60)

                    # view, add and delete user widgets in admin dashboard
                    button_view_users = tk.Button(admin_dashboard, text="View Users",bg='blue',fg='white',relief=tk.RAISED,font=('helvetica',12,'bold'),
                                                 activeforeground='white',activebackground='blue', command=view_users )
                    button_view_users.place(x=800,y=110,width=100)

                    user_listbox = tk.Listbox(admin_dashboard, height=10, width=50, fg='white', bg='black')
                    user_listbox.configure(font=('helvetica',15,'bold'),bd=0,highlightthickness=2,highlightcolor='red')
                    user_listbox.place(x=790, y=150 )

                    # report retrieval gui for the admin dashboard

                    result_text = tk.Text(admin_dashboard, wrap=tk.WORD, height=20,bg='black',fg='white',
                                          bd=0,highlightcolor='red',highlightthickness=2,width=80, state=tk.DISABLED)
                    result_text.place(x=30,y=150)
                    retrieve_button = tk.Button(admin_dashboard, text="RETRIEVE",bg='blue',fg='white',relief=tk.RAISED,font=('helvetica',12,'bold'),
                                                 activeforeground='white',activebackground='blue',command=retrieve_data)
                    retrieve_button.place(x=50,y=500)
                    save_button = tk.Button(admin_dashboard, text="Save ",bg='blue',fg='white',relief=tk.RAISED,font=('helvetica',12,'bold'),
                                            activeforeground='white',activebackground='blue',command=save_to_file)
                    save_button.place(x=160,y=500)

                    button_delete_user = tk.Button(admin_dashboard, text="Delete User",bg='red',fg='white',relief=tk.RAISED,font=('helvetica',12,'bold'),
                                                 activeforeground='white',activebackground='red',command=delete_user)
                    button_delete_user.place(x=920,y=110,width=100)

                    button_add_user_window = tk.Button(admin_dashboard, text="Add User",bg='blue',fg='white',relief=tk.RAISED,font=('helvetica',12,'bold'),
                                                 activeforeground='white',activebackground='blue',command=open_add_user_window)
                    button_add_user_window.place(x=1040,y=110,width=100)

                    print("Login successful for admin user!")
                    # Add code to proceed with admin user login

                    login_username_entry.delete(0, tk.END)
                    login_password_entry.delete(0, tk.END)

                else:
                    messagebox.showerror("Access Denied", "NOT AN ADMIN. Access denied."
                                         ,parent=admin_login_window)
            else:
                messagebox.showerror("Access Denied", "Username or password not found. Access denied.",
                                     parent=admin_login_window)
        else:
            print("User not found. Access denied.")

        # Close the cursor and connection
        cursor.close()
        connection.close()

    # create account functionality for administrator
    def create_admin_account():

        username = username_entry.get()
        password = password_entry.get()

        hashed_password = hash_password(password)
        role = 'admin'

        connection = MySQLdb.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        cursor = connection.cursor()

        query = "INSERT INTO mysystemusers (username, password, role) VALUES (%s, %s, %s)"
        data = (username, hashed_password, role)

        try:
            cursor.execute(query, data)
            connection.commit()
            print("User successfully created with admin role!")

            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

        except MySQLdb.Error as err:
            print(f"Error creating user: {err}")
        finally:
            # Close the cursor and connection
            cursor.close()
            connection.close()

    def hash_password(password):
        # Hash the password using bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed.decode('utf-8')


    # Function to open the admin login window
    admin_login_window = tk.Toplevel(root)
    admin_login_window.title('Admin Login Window')
    admin_login_window.geometry('1360x723')
    admin_login_window.configure(bg='black')

    adminbackground_image = PhotoImage(file='admin_background.png')
    adminbackground_label = tk.Label(admin_login_window, image=adminbackground_image, bd=0)
    adminbackground_label.photo = adminbackground_image
    adminbackground_label.place(x=0, y=0, relwidth=1, relheight=1)

    # label flash colors
    def flash_label(label, colors, interval, count):
        color_cycle = itertools.cycle(colors)

        def update_color():
            label.config(foreground=next(color_cycle))
            count[0] -= 1

            if count[0] > 0:
                label.after(interval, update_color)

        update_color()


    # create account widgets in admin page
    username_label = tk.Label(admin_login_window, text="Username:",background='black',foreground='white',font=('helevitica'
                                                                                ,12,'bold'))
    username_entry = tk.Entry(admin_login_window,font=('helivitica',12),fg='white',bg='black',highlightcolor='red',highlightthickness=2)
    username_entry.configure(insertbackground='white')

    password_label = tk.Label(admin_login_window, text="Password:",background='black',foreground='white',font=('helevitica'
                                                                                ,12,'bold'))

    password_entry = tk.Entry(admin_login_window, show="*",font=('helivitica',12),fg='white',bg='black',highlightcolor='red',highlightthickness=2)
    password_entry.configure(insertbackground='white')

    # login widgets for admin page
    login_username_label = tk.Label(admin_login_window, text="Username:", background='black', foreground='white',
                              font=('helevitica'
                                    , 12, 'bold'))
    login_username_entry = tk.Entry(admin_login_window, font=('helivitica', 12), fg='white', bg='black',highlightthickness=2,
                                    highlightcolor='blue')
    login_username_entry.configure(insertbackground='white')

    login_password_label = tk.Label(admin_login_window, text="Password:", background='dark red', foreground='white',
                              font=('helevitica'
                                    , 12, 'bold'))
    login_password_entry = tk.Entry(admin_login_window, show="*",fg='white', font=('helivitica', 12), bg='dark red',highlightcolor='blue',
                                    highlightthickness=2)
    login_password_entry.configure(insertbackground='white')

    admin_signup_button = tk.Button(admin_login_window, text="SignUp", activebackground='red', activeforeground='white', fg="white",
                             relief=tk.RAISED,
                             borderwidth=0, highlightthickness=0,
                             width=10, bg='red', font=('helevitica', 12, "bold"),
                             cursor='hand2', bd=0,command=create_admin_account)
    admin_signup_button.place(x=600,y=180)

    admin_login_button = tk.Button(admin_login_window, text="login", activebackground='red', activeforeground='white',
                                    fg="white",
                                    relief=tk.RAISED,
                                    borderwidth=0, highlightthickness=0,
                                    width=10, bg='red', font=('helevitica', 12, "bold"),
                                    cursor='hand2', bd=0,command=validate_admin_login)
    admin_login_button.place(x=600, y=380)



    #  layout for labels, entry fields, and button
    username_label.place(x=500,y=100)
    username_entry.place(x=600,y=100,width=250)

    password_label.place(x=500,y=140)
    password_entry.place(x=600,y=140,width=250)

    # labels for entry fields, and button for admin page
    login_username_label.place(x=500, y=300)
    login_username_entry.place(x=600, y=300,width=250)

    login_password_label.place(x=500, y=340)
    login_password_entry.place(x=600, y=340,width=250)

    label_createaccount = tk.Label(admin_login_window, text="Create Account", font=("Helvetica", 16, 'bold'), foreground='red',
                                background='black')
    label_createaccount.place(x=600,y=60)

    label_login = tk.Label(admin_login_window, text="Login into Account", font=("Helvetica", 16, 'bold'),
                                   foreground='red',
                                   background='black')
    label_login.place(x=600, y=260)

    label_adminwindow = tk.Label(admin_login_window, text="WELCOME ADMIN  🦅", font=("Helvetica", 25, 'bold'),
                           foreground='red',
                           background='black')
    label_adminwindow.place(x=50, y=60)

    # Colors to flash through
    flash_colors = ['red','blue','black']

    # Flash the label with colors for 10 cycles with an interval of 500 milliseconds
    flash_count = [10000000000000]
    flash_label(label_adminwindow, flash_colors, 800, flash_count)

# function to handle click event
def admin_login_click(event):
    open_admin_login_window()


def flash_label_color(label, colors, interval, count):
    color_cycle = itertools.cycle(colors)

    def update_color():
        label.config(foreground=next(color_cycle))
        count[0] -= 1

        if count[0] > 0:
            label.after(interval, update_color)

    update_color()


# Create main window
root = tk.Tk()
root.title("Login ")
root.configure(bg='black')
root.geometry("1360x723")  # Width x Height




background_image = PhotoImage(file ='background6.png')
background_label = tk.Label(root, image=background_image,bd=0)
background_label.place(x=0, y=0, relwidth=1, relheight=1)


label_cyberhawk = ttk.Label(root, text="CyberHawk       🦅", font=("Helvetica", 43,'bold'), foreground='red',background='black')
label_cyberhawk.place(relx=0.16, rely=0.76)
label_intelligence= ttk.Label(root, text="Intelligence", font=("Helvetica", 43,'bold'), foreground='blue',background='black')
label_intelligence.place(relx=0.57, rely=0.76)

flash_colors = ['black','red', 'blue','red']

flash_count = [20]
flash_label_color(label_cyberhawk, flash_colors, 300, flash_count.copy())
flash_label_color(label_intelligence, flash_colors, 350, flash_count)

# Disable window resizing
# root.resizable(False, False)

# Create and place widgets using pack for center alignment
username_label = tk.Label(root, text="Username:",bg='black',font=("helevitica",16,'bold'))
username_label.pack(pady=15)
username_label.config(fg='red') # change text color of the label
username_entry = tk.Entry(root,font=('helevitica',14),bg='black',fg='white',highlightthickness=2,highlightcolor='red')
username_entry.pack(pady=2,padx=5)
username_entry.configure(insertbackground='white')

password_label = tk.Label(root, text="Password:",bg='black',font=("helevitica",14,'bold'))
password_label.pack(pady=5)
password_label.config(fg='red')
password_entry = tk.Entry(root, show="*",font=('helevitca',14),bg='black',fg='WHITE',highlightcolor='red',highlightthickness=2)
password_entry.pack(pady=5)
password_entry.configure(insertbackground='white')

# loginButton_image = PhotoImage(file='login1.png')
login_button = tk.Button(root, text="Login",activebackground='red',activeforeground='white',fg="white",relief=tk.RAISED,
                         borderwidth=0,highlightthickness=0,
                          width=10,bg='red',font=('helevitica',12,"bold"), command= validate_login,cursor='hand2',bd=0)
login_button.pack(pady=10)
create_account_button = tk.Button(root, text='SignUp',relief=tk.RAISED,font=('helevitica',12,"bold"),fg='white',bg='blue',
                 width=10,   activebackground='blue',activeforeground='white',cursor="hand2",command=create_account_window)
create_account_button.pack(pady=10,padx=1)

# admin link
admin_label = tk.Label(root, text="Admin Login 🦅", fg="light blue",bg='black', cursor="hand2", font=("underline",14,'bold'))
admin_label.place(x=1130,y=45)
admin_label.bind("<Button-1>", admin_login_click) # bind click event to the label

# Run the Tkinter event loop
root.mainloop()
