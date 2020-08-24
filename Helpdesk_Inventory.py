from __future__ import division
from tkinter import *
from tkinter import messagebox
import sqlite3
from tkinter import ttk
import os
import datetime
import time
import csv
import smtplib
from subprocess import call
from sys import exit
from random import randint
from passlib.hash import pbkdf2_sha256

root = Tk()
root.title("HelpDesk Inventory")

width = 612
height = 360
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width/2) - (width/2)
y = (screen_height/2) - (height/2)
root.geometry("%dx%d+%d+%d" % (width, height, x, y))
root.resizable(0, 0)
root.config(bg="#202020")

#========================================VARIABLES========================================
USERNAME = StringVar()
PASSWORD = StringVar()
PRIVLEVEL = IntVar()
SITE = StringVar()
BUILDING = StringVar()
STORAGEROOM = StringVar()
ROOMNUMBER = StringVar()
LOCATION = StringVar()
AUDIT = StringVar()
ROW = StringVar()
RACK = StringVar()
SHELF = StringVar()
BIN = StringVar()
GROUP = StringVar()
BUSINESS = StringVar()
priv_choices = ['1 - Admin', '2 - User', '3 - Read Only']
type_choices = ['Device', 'Peripheral']
laptop_choices = ['E5450', 'E5470']
SEARCHFIELD = StringVar()
SEARCHFIELD2 = StringVar()
search_choices = ['Building', 'Room Number', 'Location', 'Business', 'Vendor', 'Part Description', 'Part Number', 'Category', 'Sub-Category']
storage_choices = ['Yes', 'No']
search_choices2 = ['User Name', 'Action', 'Title', 'Extra', 'Time Stamp']
search_choices3 = ['Vendor', 'Part Description', 'Part Number', 'Category', 'Sub-Category']
COUNT = IntVar()
MIN = IntVar()
MAX = IntVar()
AMOUNT = IntVar()
PRIVLEVEL = IntVar()
OLDPASSWORD = StringVar()
NEWPASSWORD1 = StringVar()
NEWPASSWORD2 = StringVar()
OLDUSERNAME = StringVar()
NEWUSERNAME = StringVar()
USERPRIV = StringVar()
SEARCH = StringVar()
SEARCH2 = StringVar()
SEARCH3 = StringVar()
TYPE = StringVar()
NAME = StringVar()
MODEL = StringVar()
SERIALNUM = StringVar()
LOCATION = StringVar()
STATUS = StringVar()

currentPage = IntVar()
startPos = IntVar()
endPos = IntVar()
totalPages = IntVar()

#========================================METHODS==========================================

def Database():
    global conn, cursor, path
    path = get_script_path()
    dbLocation = path + "/inventory.db"
    conn = sqlite3.connect(dbLocation)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS `users` (user_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT, password TEXT, privlevel INTEGER)")
    cursor.execute("CREATE TABLE IF NOT EXISTS `parts` (item_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, type TEXT, model TEXT, count INTEGER)")
    cursor.execute("CREATE TABLE IF NOT EXISTS 'log' (log_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT, action TEXT, title TEXT, extra TEXT, timestamp TEXT)")
    cursor.execute("SELECT * FROM `users` WHERE `username` = 'admin'")
    if cursor.fetchone() is None:
        hash = pbkdf2_sha256.hash("admin", rounds=2000, salt_size=16)
        cursor.execute("INSERT INTO `users` (username, password, privlevel) VALUES(?, ?, ?)", ('admin', hash, 1))
        conn.commit()
        messagebox.showinfo('HelpDesk Inventory', "Default 'admin' account created with password 'admin'.")

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

def Exit():
    result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to exit?', icon="warning")
    if result == 'yes':
        root.destroy()
        exit()

def Exit2():
    result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to exit?', icon="warning")
    if result == 'yes':
        Home.destroy()
        exit()

def ShowLoginForm():
    global loginform
    loginform = Toplevel()
    loginform.title("HelpDesk Inventory/Account Login")
    width = 600
    height = 400
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    loginform.resizable(0, 0)
    loginform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    loginform.config(bg="#202020")
    LoginForm()

def LoginForm():
    global lbl_result
    global lbl_result2
    global user
    TopLoginForm = Frame(loginform, width=600, height=100, bd=1, relief=SOLID)
    TopLoginForm.pack(side=TOP, pady=20)
    lbl_text = Label(TopLoginForm, text="User Login", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidLoginForm = Frame(loginform, width=600, bg="#202020")
    MidLoginForm.pack(side=TOP, pady=50)
    lbl_username = Label(MidLoginForm, text="Username:", font=('arial', 25), bd=18, fg="#BDBDBD", bg="#202020")
    lbl_username.grid(row=0)
    lbl_password = Label(MidLoginForm, text="Password:", font=('arial', 25), bd=18, fg="#BDBDBD", bg="#202020")
    lbl_password.grid(row=1)
    lbl_result = Label(MidLoginForm, text="", font=('arial', 18), bg="#202020", fg="#BDBDBD")
    lbl_result.grid(row=3, columnspan=2)
    username = Entry(MidLoginForm, textvariable=USERNAME, font=('arial', 25), width=15, highlightbackground="#202020")
    username.grid(row=0, column=1)
    password = Entry(MidLoginForm, textvariable=PASSWORD, font=('arial', 25), width=15, show="*")
    password.grid(row=1, column=1)
    Database()
    btn_login = Button(MidLoginForm, text="Login", font=('arial', 18), width=30, highlightbackground="#202020", command=Login)
    btn_login.grid(row=2, columnspan=2, pady=20)
    btn_login.bind('<Return>', Login)

def Home():
    global Home
    Home = Tk()
    Home.protocol("WM_DELETE_WINDOW", Exit)
    Home.title("HelpDesk Inventory/Home")
    width = 612
    height = 600
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    Home.geometry("%dx%d+%d+%d" % (width, height, x, y))
    Home.resizable(0, 0)
    Title = Frame(Home, bd=1, relief=SOLID)
    Title.grid(row=0, padx=40)
    lbl_display = Label(Title, text="HelpDesk Inventory", font=('arial', 35), fg="#BDBDBD", bg="#202020")
    lbl_display.grid(row=0)
    info = "User: " + str(user_name)
    lbl_info = Label(Home, text=info, font=('arial', 15), bd=18, fg="#BDBDBD", bg="#202020")
    lbl_info.grid(row=2)
    btn_viewInv = Button(Home, text="View Inventory", font=('arial', 18), width=20, pady=20, highlightbackground="#202020", command=ShowParts)
    btn_viewInv.grid(row=3, pady=10)
    btn_exit2 = Button(Home, text="Exit", font=('arial', 18), width=10, pady=20, highlightbackground="#202020", command=Exit2)
    btn_exit2.grid(row=6, pady=10)
    if privlevel == 2 or privlevel == 3:
        btn_changepass = Button(Home, text="Change Password", font=('arial', 18), width=20, pady=20, highlightbackground="#202020", command=ShowChangePass)
        btn_changepass.grid(row=4, pady=10)
    if privlevel == 1:
        btn_addnewuser = Button(Home, text="Users List", font=('arial', 18), width=20, pady=20, highlightbackground="#202020", command=ShowUserConfiguration)
        btn_addnewuser.grid(row=4, pady=10)
        btn_logs = Button(Home, text="View Log", font=('arial', 18), width=20, pady=20, highlightbackground="#202020", command=ShowLogs)
        btn_logs.grid(row=5, pady=10)
    Home.config(bg="#202020")

def Settings():
    pass


def ShowAddNewUser():
    global userform
    userform = Toplevel()
    userform.title("Add New User")
    width = 600
    height = 600
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    userform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    userform.resizable(0, 0)
    userform.config(bg="#202020")
    UserForm()

def UserForm():
    global lbl_userresult
    TopLoginForm = Frame(userform, width=600, height=100, bd=1, relief=SOLID)
    TopLoginForm.pack(side=TOP, pady=20)
    lbl_text = Label(TopLoginForm, text="Add New User", font=('arial', 18), fg="#BDBDBD", bg="#202020", width=600)
    lbl_text.pack(fill=X)
    MidUserForm = Frame(userform, width=600)
    MidUserForm.pack(side=TOP, pady=50)
    MidUserForm.config(bg="#202020")
    lbl_username = Label(MidUserForm, text="New Username:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_username.grid(row=0)
    lbl_newpassword1 = Label(MidUserForm, text="New Password:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword1.grid(row=1)
    lbl_newpassword2 = Label(MidUserForm, text="Retype Password:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword2.grid(row=2)
    lbl_userpriv = Label(MidUserForm, text="Privilege Level:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_userpriv.grid(row=3)
    newusername = Entry(MidUserForm, textvariable=NEWUSERNAME, font=('arial', 15), width=15)
    newusername.grid(row=0, column=1)
    oldpassword = Entry(MidUserForm, textvariable=NEWPASSWORD1, font=('arial', 15), width=15, show="*")
    oldpassword.grid(row=1, column=1)
    newpassword1 = Entry(MidUserForm, textvariable=NEWPASSWORD2, font=('arial', 15), width=15, show="*")
    newpassword1.grid(row=2, column=1)
    opt_priv = OptionMenu(MidUserForm, USERPRIV, *priv_choices)
    opt_priv.grid(row=3, column=1)
    opt_priv.config(width=15)
    btn_changepass = Button(MidUserForm, text="Add User", font=('arial', 18), width=30, highlightbackground="#202020", command=AddUser)
    btn_changepass.grid(row=4, columnspan=2, pady=20)
    btn_changepass.bind('<Return>', AddUser)

def AddUser():
    USERPRIV.set(int(USERPRIV.get()[0]))
    if NEWUSERNAME.get() == "" or PRIVLEVEL.get() == "":
        messagebox.showerror('New User', 'Missing information.', icon='error')
    else:
        if NEWPASSWORD1.get() != NEWPASSWORD2.get():
            messagebox.showerror('New User', 'Passwords do not match.', icon='error')
            NEWPASSWORD1.set("")
            NEWPASSWORD2.set("")
        else:
            Database()
            cursor.execute("""SELECT username FROM users WHERE username = ? """, (NEWUSERNAME.get(),))
            conn.commit
            fetch = cursor.fetchone()
            if fetch != None:
                messagebox.showerror('Error','User alrady exists', icon="error")
                NEWUSERNAME.set("")
                NEWPASSWORD1.set("")
                NEWPASSWORD2.set("")
                USERPRIV.set("")
            else:
                hash = pbkdf2_sha256.hash(NEWPASSWORD1.get(), rounds=2000, salt_size=16)
                cursor.execute("INSERT INTO `users` (username, password, privlevel) VALUES(?, ?, ?)", (str(NEWUSERNAME.get()), hash, int(USERPRIV.get())))
                conn.commit()
                logname = NEWUSERNAME.get()
                privilege = 'Privilege ' + str(USERPRIV.get())
                NEWUSERNAME.set("")
                NEWPASSWORD1.set("")
                NEWPASSWORD2.set("")
                USERPRIV.set("")
                cursor.close()
                conn.close()
                messagebox.showinfo('New User', 'User added successfully.', icon='info')
                Log('Created User',logname, privilege)
                userform.withdraw()
    Reset2()

def SelectUserPass():
    if not tree2.selection():
       print("ERROR")
    else:
        curItem = tree2.focus()
        contents =(tree2.item(curItem))
        selecteditem = contents['values']
        passLocation = contents['values'][1]
        OLDUSERNAME.set(passLocation)
        ShowChangePass()

def ShowChangePass():
    global passform
    passform = Toplevel()
    passform.title("Change Password")
    width = 600
    height = 600
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    passform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    passform.resizable(0, 0)
    passform.config(bg="#202020")
    if privlevel == 1:
        AdminPassForm()
    else:
        PassForm()

def PassForm():
    global lbl_passresult
    TopLoginForm = Frame(passform, width=600, height=100, bd=1, relief=SOLID)
    TopLoginForm.pack(side=TOP, pady=20)
    lbl_text = Label(TopLoginForm, text="Change Password", font=('arial', 18), fg="#BDBDBD", bg="#202020", width=600)
    lbl_text.pack(fill=X)
    MidLoginForm = Frame(passform, width=600)
    MidLoginForm.pack(side=TOP, pady=50)
    MidLoginForm.config(bg="#202020")
    lbl_username = Label(MidLoginForm, text="Username:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_username.grid(row=0)
    lbl_username2 = Label(MidLoginForm, text=user_name, font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_username2.grid(row=0, column=1)
    OLDUSERNAME.set(user_name)
    lbl_oldpassword = Label(MidLoginForm, text="Current Password:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_oldpassword.grid(row=1)
    lbl_newpassword1 = Label(MidLoginForm, text="New Password:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword1.grid(row=2)
    lbl_newpassword2 = Label(MidLoginForm, text="Retype Password:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword2.grid(row=3)
    lbl_passresult = Label(MidLoginForm, text="", font=('arial', 18), bg="#202020")
    lbl_passresult.grid(row=5, columnspan=2)
    oldpassword = Entry(MidLoginForm, textvariable=OLDPASSWORD, font=('arial', 25), width=15, show="*")
    oldpassword.grid(row=1, column=1)
    newpassword1 = Entry(MidLoginForm, textvariable=NEWPASSWORD1, font=('arial', 25), width=15, show="*")
    newpassword1.grid(row=2, column=1)
    newpassword2 = Entry(MidLoginForm, textvariable=NEWPASSWORD2, font=('arial', 25), width=15, show="*")
    newpassword2.grid(row=3, column=1)
    btn_changepass = Button(MidLoginForm, text="Change Password", font=('arial', 18), width=30, highlightbackground="#202020", command=ChangePass)
    btn_changepass.grid(row=4, columnspan=2, pady=20)
    btn_changepass.bind('<Return>', ChangePass)

def AdminPassForm():
    global lbl_adminpassresult
    TopLoginForm = Frame(passform, width=600, height=100, bd=1, relief=SOLID)
    TopLoginForm.pack(side=TOP, pady=20)
    lbl_text = Label(TopLoginForm, text="Change Password", font=('arial', 18), fg="#BDBDBD", bg="#202020", width=600)
    lbl_text.pack(fill=X)
    MidLoginForm = Frame(passform, width=600)
    MidLoginForm.pack(side=TOP, pady=50)
    MidLoginForm.config(bg="#202020")
    lbl_username = Label(MidLoginForm, text="Username:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_username.grid(row=0, column=0)
    lbl_newpassword1 = Label(MidLoginForm, text="New Password:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword1.grid(row=2, column=0)
    lbl_newpassword2 = Label(MidLoginForm, text="Retype Password:", font=('arial', 25), fg="#BDBDBD", bg="#202020", bd=18)
    lbl_newpassword2.grid(row=3, column=0)
    lbl_adminpassresult = Label(MidLoginForm, text="", font=('arial', 18), fg="#BDBDBD", bg="#202020")
    lbl_adminpassresult.grid(row=5, columnspan=2)
    lbl_selectedname = Label(MidLoginForm, text=OLDUSERNAME.get(), font=('arial', 25), width=15, fg="#BDBDBD", bg="#202020")
    lbl_selectedname.grid(row=0, column=1)
    newpassword1 = Entry(MidLoginForm, textvariable=NEWPASSWORD1, font=('arial', 25), width=15, show="*")
    newpassword1.grid(row=2, column=1)
    newpassword2 = Entry(MidLoginForm, textvariable=NEWPASSWORD2, font=('arial', 25), width=15, show="*")
    newpassword2.grid(row=3, column=1)
    btn_changepass = Button(MidLoginForm, text="Change Password", font=('arial', 18), width=30, highlightbackground="#202020", command=AdminChangePass)
    btn_changepass.grid(row=4, columnspan=2, pady=20)
    btn_changepass.bind('<Return>', AdminChangePass)

def ChangePass(event=None):
    if NEWPASSWORD1.get() != "" or NEWPASSWORD2.get() != "":
        if NEWPASSWORD1.get() == NEWPASSWORD2.get():
            Database()
            cursor.execute("""SELECT password FROM users WHERE username COLLATE NOCASE = ? """, (OLDUSERNAME.get(),))
            conn.commit
            fetch = cursor.fetchall()
            if len(fetch) == 0:
                lbl_passresult.config(text="Username not found", fg="red")
            else:
                lbl_passresult.config(text="")
                currentpass = fetch[0]
                currentpass = currentpass[0]
                hash = pbkdf2_sha256.hash(OLDPASSWORD.get(), rounds=2000, salt_size=16)
                if pbkdf2_sha256.verify(OLDPASSWORD.get(), currentpass):
                    hash = pbkdf2_sha256.hash(NEWPASSWORD1.get(), rounds=2000, salt_size=16)
                    cursor.execute("""UPDATE users SET password = ? WHERE username COLLATE NOCASE = ? """, (hash, OLDUSERNAME.get()))
                    conn.commit()
                    logname = OLDUSERNAME.get()
                    OLDPASSWORD.set("")
                    NEWPASSWORD1.set("")
                    NEWPASSWORD2.set("")
                    lbl_passresult.config(text="Password successfully changed", fg="#BDBDBD", bg="#202020")
                    passform.withdraw()
                    Log('Changed Password',logname, "")
                else:
                    lbl_passresult.config(text="Current password does not match", fg="red")
        else:
            lbl_passresult.config(text="Password doesn't match", fg="red")
    else:
        lbl_passresult.config(text="Password fields cannot be blank", fg="red")
    conn.close()

def AdminChangePass(event=None):
    if NEWPASSWORD1.get() == NEWPASSWORD2.get():
        Database()
        cursor.execute("""SELECT password FROM users WHERE username = ? """, (OLDUSERNAME.get(),))
        conn.commit
        fetch = cursor.fetchone()
        if len(fetch) == 0:
            lbl_adminpassresult.config(text="Username not found", fg="red")
        else:
            lbl_adminpassresult.config(text="")
            hash = pbkdf2_sha256.hash(NEWPASSWORD1.get(), rounds=2000, salt_size=16)
            cursor.execute("""UPDATE users SET password = ? WHERE username = ? """, (hash, OLDUSERNAME.get()))
            conn.commit()
            logname = OLDUSERNAME.get()
            NEWPASSWORD1.set("")
            NEWPASSWORD2.set("")
            lbl_adminpassresult.config(text="Password successfully changed", fg="#BDBDBD")
            Log('Changed Password',logname, "")
    else:
        lbl_adminpassresult.config(text="Password doesn't match", fg="red")
    Reset2()

def EditSelect():
    global editSelect
    if not tree.selection():
        print("ERROR")
    else:
        curItem = tree.focus()
        contents = (tree.item(curItem))
        editSelect = contents['values']
        STORAGE.set(editSelect[10])
        ShowEdit()

def ShowEdit():
    global editForm
    editForm = Toplevel()
    editForm.title("Edit Item")
    width = 400
    height = 650
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    editForm.geometry("%dx%d+%d+%d" % (width, height, x, y))
    editForm.resizable(0, 0)
    EditForm()

def ShowSku():
    global skuForm
    skuForm = Toplevel()
    skuForm.title("New Part")
    width = 400
    height = 400
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    skuForm.geometry("%dx%d+%d+%d" % (width, height, x, y))
    skuForm.resizable(0, 0)
    SkuForm()

def SkuForm():
    TopAddNew = Frame(skuForm, width=400, height=100, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    skuForm.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="New Part", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew3 = Frame(skuForm, width=600)
    MidAddNew3.pack(side=TOP, pady=30)
    MidAddNew3.config(bg="#202020")
    lbl_type = Label(MidAddNew3, text="Type", font=('arial', 10), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_type.grid(row=0, column=0, sticky=W)
    lbl_model = Label(MidAddNew3, text="Model", font=('arial', 10), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_model.grid(row=1, column=0, sticky=W)
    lbl_count= Label(MidAddNew3, text="Count", font=('arial', 10), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_count.grid(row=2, column=0, sticky=W)
    opt_type = OptionMenu(MidAddNew3, TYPE, *type_choices)
    opt_type.grid(row=0, column=1)
    opt_type.config(width=15)
    ent_model = Entry(MidAddNew3, textvariable=MODEL, font=('arial', 10),width=15)
    ent_model.grid(row=1, column=1)
    ent_count = Entry(MidAddNew3, textvariable=COUNT, font=('arial', 10),width=15)
    ent_count.grid(row=2, column=1)
    btn_addsku = Button(MidAddNew3, text="Add", font=('arial', 12), width=30, highlightbackground="#202020", command=NewSku)
    btn_addsku.grid(row=4, columnspan=2, pady=10)
    btn_cancelsku = Button(MidAddNew3, text="Cancel", font=('arial', 12), width=30, highlightbackground="#202020", command=CancelSku)
    btn_cancelsku.grid(row=5, columnspan=2, pady=10)


def EditForm():
    global lbl_editupdate
    TopAddNew = Frame(editForm, width=600, height=100, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    editForm.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="Edit Item", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew2 = Frame(editForm, width=600)
    MidAddNew2.pack(side=TOP, pady=50)
    MidAddNew2.config(bg="#202020")
    lbl_building = Label(MidAddNew2, text="Building:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_building.grid(row=0, column=0, sticky=W)
    lbl_roomnum = Label(MidAddNew2, text="Room #:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_roomnum.grid(row=1, column=0, sticky=W)
    lbl_location = Label(MidAddNew2, text="Location:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_location.grid(row=2, column=0, sticky=W)
    lbl_business = Label(MidAddNew2, text="Business Group:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_business.grid(row=3, column=0, sticky=W)
    lbl_vendor = Label(MidAddNew2, text="Vendor:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_vendor.grid(row=4, column=0, sticky=W)
    lbl_partdesc = Label(MidAddNew2, text="Part Description:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partdesc.grid(row=5, column=0, sticky=W)
    lbl_partnum = Label(MidAddNew2, text="Part Number:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partnum.grid(row=6, column=0, sticky=W)
    lbl_category = Label(MidAddNew2, text="Category:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_category.grid(row=7, column=0, sticky=W)
    lbl_subcat = Label(MidAddNew2, text="Sub-Category:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_subcat.grid(row=8, column=0, sticky=W)
    lbl_count2 = Label(MidAddNew2, text="Count:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_count2.grid(row=9, column=0, sticky=W)
    lbl_storage2 = Label(MidAddNew2, text="Storage:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_storage2.grid(row=10, column=0, sticky=W)
    BUILDING.set(editSelect[1])
    opt_building = OptionMenu(MidAddNew2, BUILDING, *building_choices)
    opt_building.grid(row=0, column=1)
    opt_building.config(bg = "#202020", width=15)
    ROOMNUMBER.set(editSelect[2])
    opt_room = OptionMenu(MidAddNew2, ROOMNUMBER, *room_choices)
    opt_room.grid(row=1, column=1)
    opt_room.config(bg = "#202020", width=15)
    ent_location = Entry(MidAddNew2, textvariable=LOCATION, font=('arial', 15), width=15)
    ent_location.grid(row=2, column=1)
    ent_location.delete(0, END)
    ent_location.insert(0, editSelect[3])
    BUSINESS.set(editSelect[4])
    opt_business = OptionMenu(MidAddNew2, BUSINESS, *business_choices)
    opt_business.grid(row=3, column=1)
    opt_business.config(bg = "#202020", width=15)
    lbl_vendor2 = Label(MidAddNew2, text=editSelect[5], font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_vendor2.grid(row=4, column=1)
    lbl_partdesc2 = Label(MidAddNew2, text=editSelect[6], font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT,  bd=10)
    lbl_partdesc2.grid(row=5, column=1)
    lbl_partnum2 = Label(MidAddNew2, text=editSelect[7], font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT,  bd=10)
    lbl_partnum2.grid(row=6, column=1)
    lbl_category2 = Label(MidAddNew2, text=editSelect[8], font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT,  bd=10)
    lbl_category2.grid(row=7, column=1)
    lbl_subcat2 = Label(MidAddNew2, text=editSelect[9], font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT,  bd=10)
    lbl_subcat2.grid(row=8, column=1)
    ent_count2 = Entry(MidAddNew2, textvariable=COUNT, font=('arial', 15), width=15)
    ent_count2.grid(row=9, column=1)
    ent_count2.delete(0, END)
    ent_count2.insert(0, editSelect[10])
    STORAGE.set(editSelect[11])
    chk_storage = Checkbutton(MidAddNew2, variable=STORAGE, onvalue="Yes", offvalue="No", bg="#009ACD", highlightbackground="#202020")
    chk_storage.grid(row=12, column=1)
    chk_storage.config(bg = "#202020", width=15)
    btn_add = Button(MidAddNew2, text="Update", font=('arial', 18), width=30, bg="#009ACD", highlightbackground="#202020", command=Update)
    btn_add.grid(row=13, columnspan=2, pady=20)

def Update():
    if CURRENTBUS.get() == "Parts":
        UpdateParts()
    if CURRENTBUS.get() == "BG3":
        UpdatePie()
    if CURRENTBUS.get() == "BG4":
        UpdateTer()
    if CURRENTBUS.get() == "BG5":
        UpdateTri()
    if CURRENTBUS.get() == "BG2":
        UpdateAmp()
    if CURRENTBUS.get() == "Seed":
        UpdateSeed()

def UpdateParts():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "":
        messagebox.showerror('Part Edit', 'Please complete missing field!.', icon='error')
    else:
        if BUILDING.get() == editSelect[1] and ROOMNUMBER.get() == str(editSelect[2]) and LOCATION.get() == editSelect[3]:
            cursor.execute("""UPDATE Parts SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
            conn.commit()
            setLocation = str(editSelect[1]) + "//" + str(editSelect[2]) + "//" + str(editSelect[3])
            Log('Updated part', editSelect[6], setLocation)
            SendEmail('Updated part', editSelect[6], setLocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            editForm.withdraw()
            messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
        else:
            cursor.execute("SELECT * FROM `Parts` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
            if cursor.fetchone() is not None:
                messagebox.showerror('Part Edit', 'Location is already in use', icon='error')
                BUILDING.set("")
                LOCATION.set("")
                ROOMNUMBER.set("")
            else:
                cursor.execute("""UPDATE Parts SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
                conn.commit()
                Log('Updated part', editSelect[6], LOCATION.get())
                SendEmail('Updated part', editSelect[6], LOCATION.get(), str(BUSINESS.get()))
                BUILDING.set("")
                ROOMNUMBER.set("")
                LOCATION.set("")
                BUSINESS.set("")
                VENDOR.set("")
                PARTDESC.set("")
                PARTNUM.set("")
                CATEGORY.set("")
                SUBCATEGORY.set("")
                COUNT.set("")
                STORAGE.set("")
                editForm.withdraw()
                messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
    ResetParts()

def UpdatePie():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "":
        messagebox.showerror('Part Edit', 'Please complete missing field!.', icon='error')
    else:
        if BUILDING.get() == editSelect[1] and ROOMNUMBER.get() == str(editSelect[2]) and LOCATION.get() == editSelect[3]:
            cursor.execute("""UPDATE piesiri SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
            conn.commit()
            setLocation = str(editSelect[1]) + "//" + str(editSelect[2]) + "//" + str(editSelect[3])
            Log('Updated part', editSelect[6], setLocation)
            SendEmail('Updated part', editSelect[6], setLocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            editForm.withdraw()
            messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
        else:
            cursor.execute("SELECT * FROM `piesiri` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
            if cursor.fetchone() is not None:
                messagebox.showerror('Part Edit', 'Location is already in use', icon='error')
                BUILDING.set("")
                LOCATION.set("")
                ROOMNUMBER.set("")
            else:
                cursor.execute("""UPDATE piesiri SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
                conn.commit()
                Log('Updated part', editSelect[6], LOCATION.get())
                SendEmail('Updated part', editSelect[6], LOCATION.get(), str(BUSINESS.get()))
                BUILDING.set("")
                ROOMNUMBER.set("")
                LOCATION.set("")
                BUSINESS.set("")
                VENDOR.set("")
                PARTDESC.set("")
                PARTNUM.set("")
                CATEGORY.set("")
                SUBCATEGORY.set("")
                COUNT.set("")
                STORAGE.set("")
                editForm.withdraw()
                messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
    ResetPie()

def UpdateTer():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "":
        messagebox.showerror('Part Edit', 'Please complete missing field!.', icon='error')
    else:
        if BUILDING.get() == editSelect[1] and ROOMNUMBER.get() == str(editSelect[2]) and LOCATION.get() == editSelect[3]:
            cursor.execute("""UPDATE BG4 SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
            conn.commit()
            setLocation = str(editSelect[1]) + "//" + str(editSelect[2]) + "//" + str(editSelect[3])
            Log('Updated part', editSelect[6], setLocation)
            SendEmail('Updated part', editSelect[6], setLocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            editForm.withdraw()
            messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
        else:
            cursor.execute("SELECT * FROM `BG4` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
            if cursor.fetchone() is not None:
                messagebox.showerror('Part Edit', 'Location is already in use', icon='error')
                BUILDING.set("")
                LOCATION.set("")
                ROOMNUMBER.set("")
            else:
                cursor.execute("""UPDATE BG4 SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
                conn.commit()
                Log('Updated part', editSelect[6], LOCATION.get())
                SendEmail('Updated part', editSelect[6], LOCATION.get(), str(BUSINESS.get()))
                BUILDING.set("")
                ROOMNUMBER.set("")
                LOCATION.set("")
                BUSINESS.set("")
                VENDOR.set("")
                PARTDESC.set("")
                PARTNUM.set("")
                CATEGORY.set("")
                SUBCATEGORY.set("")
                COUNT.set("")
                STORAGE.set("")
                editForm.withdraw()
                messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
    ResetTer()

def UpdateTri():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "":
        messagebox.showerror('Part Edit', 'Please complete missing field!.', icon='error')
    else:
        if BUILDING.get() == editSelect[1] and ROOMNUMBER.get() == str(editSelect[2]) and LOCATION.get() == editSelect[3]:
            cursor.execute("""UPDATE BG5 SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
            conn.commit()
            setLocation = str(editSelect[1]) + "//" + str(editSelect[2]) + "//" + str(editSelect[3])
            Log('Updated part', editSelect[6], setLocation)
            SendEmail('Updated part', editSelect[6], setLocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            editForm.withdraw()
            messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
        else:
            cursor.execute("SELECT * FROM `BG5` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
            if cursor.fetchone() is not None:
                messagebox.showerror('Part Edit', 'Location is already in use', icon='error')
                BUILDING.set("")
                LOCATION.set("")
                ROOMNUMBER.set("")
            else:
                cursor.execute("""UPDATE BG5 SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
                conn.commit()
                Log('Updated part', editSelect[6], LOCATION.get())
                SendEmail('Updated part', editSelect[6], LOCATION.get(), str(BUSINESS.get()))
                BUILDING.set("")
                ROOMNUMBER.set("")
                LOCATION.set("")
                BUSINESS.set("")
                VENDOR.set("")
                PARTDESC.set("")
                PARTNUM.set("")
                CATEGORY.set("")
                SUBCATEGORY.set("")
                COUNT.set("")
                STORAGE.set("")
                editForm.withdraw()
                messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
    ResetTri()

def UpdateAmp():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "":
        messagebox.showerror('Part Edit', 'Please complete missing field!.', icon='error')
    else:
        if BUILDING.get() == editSelect[1] and ROOMNUMBER.get() == str(editSelect[2]) and LOCATION.get() == editSelect[3]:
            cursor.execute("""UPDATE amp SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
            conn.commit()
            setLocation = str(editSelect[1]) + "//" + str(editSelect[2]) + "//" + str(editSelect[3])
            Log('Updated part', editSelect[6], setLocation)
            SendEmail('Updated part', editSelect[6], setLocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            editForm.withdraw()
            messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
        else:
            cursor.execute("SELECT * FROM `amp` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
            if cursor.fetchone() is not None:
                messagebox.showerror('Part Edit', 'Location is already in use', icon='error')
                BUILDING.set("")
                LOCATION.set("")
                ROOMNUMBER.set("")
            else:
                cursor.execute("""UPDATE amp SET building = ?, roomnumber = ?, location = ?, business = ?, vendor = ?, partdesc = ?, partnum = ?, category = ?, subcategory = ?, count = ?, storage = ? WHERE item_id = ? """, (str(BUILDING.get()), str(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(editSelect[5]), str(editSelect[6]), str(editSelect[7]), str(editSelect[8]), str(editSelect[9]), int(COUNT.get()), str(STORAGE.get()), int(editSelect[0])))
                conn.commit()
                Log('Updated part', editSelect[6], LOCATION.get())
                SendEmail('Updated part', editSelect[6], LOCATION.get(), str(BUSINESS.get()))
                BUILDING.set("")
                ROOMNUMBER.set("")
                LOCATION.set("")
                BUSINESS.set("")
                VENDOR.set("")
                PARTDESC.set("")
                PARTNUM.set("")
                CATEGORY.set("")
                SUBCATEGORY.set("")
                COUNT.set("")
                STORAGE.set("")
                editForm.withdraw()
                messagebox.showinfo('Part Edit', 'Successfully updated the part.', icon='info')
    ResetAmp()

def ShowCheckInOutSelect():
    global checkSelect
    if not tree.selection():
        print("ERROR")
    else:
        curItem = tree.focus()
        contents = (tree.item(curItem))
        checkSelect = contents['values']
        ShowCheckInOut()

def ShowCheckInOut():
    global addnewcheck
    addnewcheck = Toplevel()
    addnewcheck.title("Check In/Out")
    width = 600
    height = 400
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    addnewcheck.geometry("%dx%d+%d+%d" % (width, height, x, y))
    addnewcheck.resizable(0, 0)
    AddNewCheck()

def AddNewCheck():
    global lbl_update
    TopAddNew = Frame(addnewcheck, width=600, height=100, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    addnewcheck.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="Check In/Out", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew2 = Frame(addnewcheck, width=600)
    MidAddNew2.pack(side=TOP, pady=50)
    MidAddNew2.config(bg="#202020")
    lbl_partdesc = Label(MidAddNew2, text="Part Number:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partdesc.grid(row=0, column=0, sticky=W)
    lbl_location = Label(MidAddNew2, text="Location:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_location.grid(row=1, column=0, sticky=W)
    lbl_amount = Label(MidAddNew2, text="Amount:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_amount.grid(row=2, column=0, sticky=W)
    lbl_partdesc2 = Label(MidAddNew2, text=checkSelect[6][0:30], font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partdesc2.grid(row=0, column=1, sticky=W)
    lbl_location2 = Label(MidAddNew2, text=str(checkSelect[1]) + " / " + str(checkSelect[2]) + " / " + str(checkSelect[3]), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_location2.grid(row=1, column=1, sticky=W)
    ent_amount = Entry(MidAddNew2, textvariable=AMOUNT, font=('arial', 15), width=15)
    ent_amount.grid(row=2, column=1)
    btn_add = Button(MidAddNew2, text="Add", font=('arial', 18), width=10, bg="#009ACD", highlightbackground="#202020", command=CheckIn)
    btn_add.grid(row=12, column=0, pady=20)
    btn_minus = Button(MidAddNew2, text="Remove", font=('arial', 18), width=10, bg="#009ACD", highlightbackground="#202020", command=CheckOut)
    btn_minus.grid(row=12, column=1, pady=20)
    lbl_update = Label(MidAddNew2, text="", font=('arial', 18), bg="#202020")
    lbl_update.grid(row=14, columnspan=2, pady=20)

def CheckOut():
    if CURRENTBUS.get() == "Parts":
        CheckOutParts()

def CheckOutParts():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM Parts WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE Parts SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM Parts WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM Parts WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetParts()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckOutPie():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM piesiri WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE piesiri SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM piesiri WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM piesiri WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetPie()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckOutTer():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM BG4 WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE BG4 SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM BG4 WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM BG4 WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetTer()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckOutTri():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM BG5 WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE BG5 SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM BG5 WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM BG5 WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetTri()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckOutAmp():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM amp WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE amp SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM amp WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM amp WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetAmp()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckOutSeed():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM seed WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check Out', 'Location not found',icon='error')
        else:
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            newAmount = fetch[0]
            newAmount = newAmount[0]
            addedAmount = newAmount
            newAmount -= AMOUNT.get()
            if newAmount < 0:
                newAmount = 0
            cursor.execute("""UPDATE seed SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check Out', 'Successfully updated inventory')
            addnewcheck.withdraw()
            cursor.execute("""SELECT * FROM seed WHERE item_id = ?""", (checkSelect[0],))
            conn.commit()
            fetch = cursor.fetchone()
            partnum = fetch[7]
            business = fetch[4]
            if newAmount <= 10:
                cursor.execute("""SELECT * FROM seed WHERE business = ? AND partnum = ? AND storage = ?""", (business, partnum, 'Yes'))
                conn.commit()
                fetch = cursor.fetchone()
                if fetch is None:
                    print("Nothing in storage")
                else:
                    SendEmail('Need to move parts from storage.', partnum, setemailLocation, business)
            cursor.close()
            conn.close()
            ResetSeed()
            Log('Removed Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Removed Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckIn():
    if CURRENTBUS.get() == "Parts":
        CheckInParts()
    if CURRENTBUS.get() == "BG3":
        CheckInPie()
    if CURRENTBUS.get() == "BG4":
        CheckInTer()
    if CURRENTBUS.get() == "BG5":
        CheckInTri()
    if CURRENTBUS.get() == "BG2":
        CheckInAmp()
    if CURRENTBUS.get() == "Seed":
        CheckInSeed()

def CheckInParts():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM Parts WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE Parts SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetParts()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckInPie():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM piesiri WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE piesiri SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetPie()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckInTer():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM BG4 WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE BG4 SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetTer()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckInTri():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM BG5 WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE BG5 SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetTri()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckInAmp():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM amp WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE amp SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetAmp()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")

def CheckInSeed():
    lbl_update.config(text="")
    if AMOUNT.get() != 0:
        Database()
        cursor.execute("""SELECT count FROM seed WHERE item_id = ? """, (checkSelect[0],))
        conn.commit
        fetch = cursor.fetchall()
        if len(fetch) == 0:
            messagebox.showerror('Check In', 'Location not found',icon='error')
        else:
            newAmount = fetch[0]
            newAmount = newAmount[0]
            amountRemoved = newAmount
            newAmount += AMOUNT.get()
            cursor.execute("""UPDATE seed SET count = ? WHERE item_id = ? """, (newAmount, checkSelect[0]))
            conn.commit()
            messagebox.showinfo('Check In', 'Successfully updated inventory',icon='info')
            setLocation = str(checkSelect[1]) + "//" + str(checkSelect[2]) + "//" + str(checkSelect[3])
            addnewcheck.withdraw()
            cursor.close()
            conn.close()
            ResetSeed()
            Log('Added Qty', str(AMOUNT.get()), setLocation)
            SendEmail('Added Qty', str(AMOUNT.get()), setLocation, str(checkSelect[4]))
            AMOUNT.set("")
            LOCATION.set("")


def ShowAudit():
    global auditnewform
    auditnewform = Toplevel()
    auditnewform.title("HelpDesk Inventory/Audit")
    width = 300
    height = 300
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    auditnewform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    auditnewform.resizable(0, 0)
    AuditGet2()

def AuditGet2():
    TopAddNew = Frame(auditnewform, width=200, height=50, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    TopAddNew.config(bg="#202020")
    auditnewform.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="Audit", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew = Frame(auditnewform, width=600)
    MidAddNew.pack(side=TOP, pady=20)
    MidAddNew.config(bg="#202020")
    currentPageTitle = ("Audit Pg " + str(currentPage.get()) + "/" + str(totalPages.get()))
    global auditfetch
    Database()
    cursor.execute("SELECT * FROM 'item'")
    fetch = cursor.fetchall()
    audit_length = len(fetch)
    conn.close()

    print(audit_length)

    ### finish audit here

    Button(MidAddNew, text='Save', command=save_changes, highlightbackground='#202020').grid(row=16, column=0)

def save_changes():

    for i in value_list: # access the list of stringvars
        print(i.get())

def ShowAddNew():
    global addnewform
    addnewform = Toplevel()
    addnewform.title("HelpDesk Inventory/Add new")
    width = 400
    height = 700
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    addnewform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    addnewform.resizable(0, 0)
    AddNewForm()

def AuditGet():
    global auditfetch
    Database()
    cursor.execute("SELECT * FROM 'item'")
    fetch = cursor.fetchall()
    conn.close()


def AuditNewForm():
    global audit_entries
    audit_entries = []
    TopAddNew = Frame(auditnewform, width=600, height=100, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    TopAddNew.config(bg="#202020")
    auditnewform.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="Audit", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew = Frame(auditnewform, width=600)
    MidAddNew.pack(side=TOP, pady=50)
    MidAddNew.config(bg="#202020")
    currentPageTitle = ("Audit Pg " + str(currentPage.get()) + "/" + str(totalPages.get()))
    lbl_audit0 = Label(MidAddNew, text=AUDIT1.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit0.grid(row=0, sticky=W)
    lbl_audit1 = Label(MidAddNew, text=AUDIT2.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit1.grid(row=1, sticky=W)
    lbl_audit2 = Label(MidAddNew, text=AUDIT3.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit2.grid(row=2, sticky=W)
    lbl_audit3 = Label(MidAddNew, text=AUDIT4.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit3.grid(row=3, sticky=W)
    lbl_audit4 = Label(MidAddNew, text=AUDIT5.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit4.grid(row=4, sticky=W)
    lbl_audit5 = Label(MidAddNew, text=AUDIT6.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit5.grid(row=5, sticky=W)
    lbl_audit6 = Label(MidAddNew, text=AUDIT7.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit6.grid(row=6, sticky=W)
    lbl_audit7 = Label(MidAddNew, text=AUDIT8.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit7.grid(row=7, sticky=W)
    lbl_audit8 = Label(MidAddNew, text=AUDIT9.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit8.grid(row=8, sticky=W)
    lbl_audit9 = Label(MidAddNew, text=AUDIT10.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_audit9.grid(row=9, sticky=W)
    ent_audit0 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit0.grid(row=0, column=1)
    ent_audit1 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit1.grid(row=1, column=1)
    ent_audit2 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit2.grid(row=2, column=1)
    ent_audit3 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit3.grid(row=3, column=1)
    ent_audit4 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit4.grid(row=4, column=1)
    ent_audit5 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit5.grid(row=5, column=1)
    ent_audit6 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit6.grid(row=6, column=1)
    ent_audit7 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit7.grid(row=7, column=1)
    ent_audit8 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit8.grid(row=8, column=1)
    ent_audit9 = Entry(MidAddNew, font=('arial', 15), width=5, highlightbackground="#BDBDBD")
    ent_audit9.grid(row=9, column=1)
    if currentPage.get() != totalPages.get():
        btn_prev = Button(MidAddNew, text="Previous", font=('arial', 18), width=10, pady=40, padx=20, bg="#009ACD", highlightbackground="#202020", command= lambda: Previous(currentPage))
        btn_prev.grid(row=14, column=0)
        btn_next = Button(MidAddNew, text="Next", font=('arial', 18), width=10, pady=40, padx=20, bg="#009ACD", highlightbackground="#202020", command = Next)
        btn_next.grid(row=14, column=1)
    else:
        btn_audit = Button(MidAddNew, text="Submit", font=('arial', 18), width=30, bg="#009ACD", highlightbackground="#202020", command=Submit)
        btn_audit.grid(row=(len(fetch)+1), columnspan=2, pady=20)

def Previous():
    pass

def Next(event=None):
    print ("Current Page = " + str(currentPage.get()))
    currentPage.set(currentPage.get() + 1)
    startPos.set(startPos.get() + 10)
    endPos.set(endPos.get() + 10)

def Submit():
    for x in range(0, 5):
        value = audit_entries[x].get()
        print(value)

def AddNewForm():
    global lbl_addnewstatus
    TopAddNew = Frame(addnewform, width=600, height=100, bd=1, relief=SOLID)
    TopAddNew.pack(side=TOP, pady=20)
    TopAddNew.config(bg="#202020")
    addnewform.config(bg="#202020")
    lbl_text = Label(TopAddNew, text="Add Part", font=('arial', 18), width=600, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    MidAddNew = Frame(addnewform, width=600)
    MidAddNew.pack(side=TOP, pady=50)
    MidAddNew.config(bg="#202020")
    lbl_building = Label(MidAddNew, text="Building:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_building.grid(row=0, sticky=W)
    lbl_room = Label(MidAddNew, text="Room:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_room.grid(row=1, sticky=W)
    lbl_location = Label(MidAddNew, text="Location:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_location.grid(row=2, sticky=W)
    lbl_business = Label(MidAddNew, text="Business Group:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_business.grid(row=3, sticky=W)
    lbl_vendor = Label(MidAddNew, text="Vendor", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_vendor.grid(row=4, sticky=W)
    lbl_partdesc = Label(MidAddNew, text="Part Description:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partdesc.grid(row=5, sticky=W)
    lbl_partnum = Label(MidAddNew, text="Part Number:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_partnum.grid(row=6, sticky=W)
    lbl_category = Label(MidAddNew, text="Category:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_category.grid(row=7, sticky=W)
    lbl_subcat = Label(MidAddNew, text="Sub-Category:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_subcat.grid(row=8, sticky=W)
    lbl_count = Label(MidAddNew, text="Count:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_count.grid(row=11, sticky=W)
    lbl_storage = Label(MidAddNew, text="Storage:", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_storage.grid(row=12, sticky=W)
    lbl_addnewstatus = Label(MidAddNew, text="", font=('arial', 15), fg="#BDBDBD", bg="#202020", bd=10)
    lbl_addnewstatus.grid(row=14, sticky=W)
    BUILDING.set("")
    ROOMNUMBER.set("")
    LOCATION.set("")
    BUSINESS.set("")
    COUNT.set("")
    STORAGE.set("No")
    opt_building = OptionMenu(MidAddNew, BUILDING, *building_choices)
    opt_building.grid(row=0, column=1)
    opt_building.config(bg = "#202020", width=15)
    opt_room = OptionMenu(MidAddNew, ROOMNUMBER, *room_choices)
    opt_room.grid(row=1, column=1)
    opt_room.config(bg = "#202020", width=15)
    ent_location = Entry(MidAddNew, textvariable=LOCATION, font=('arial', 15), width=15)
    ent_location.grid(row=2, column=1)
    if SEND_BUSINESS.get() == "All":
        opt_business = OptionMenu(MidAddNew, BUSINESS, *business_choices)
        opt_business.grid(row=3, column=1)
        opt_business.config(bg = "#202020", width=15)
    else:
        BUSINESS.set(SEND_BUSINESS.get())
        lbl_business = Label(MidAddNew, text=BUSINESS.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
        lbl_business.grid(row=3, column=1)
    lbl_vendor2 = Label(MidAddNew, text=VENDOR.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_vendor2.grid(row=4, column=1)
    lbl_partdesc2 = Label(MidAddNew, text=PARTDESC.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_partdesc2.grid(row=5, column=1)
    lbl_partnum2 = Label(MidAddNew, text=PARTNUM.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_partnum2.grid(row=6, column=1)
    lbl_category2 = Label(MidAddNew, text=CATEGORY.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_category2.grid(row=7, column=1)
    lbl_subcat2 = Label(MidAddNew, text=SUBCATEGORY.get(), font=('arial', 15), fg="#BDBDBD", bg="#202020", width=15, anchor=W, justify=LEFT, bd=10)
    lbl_subcat2.grid(row=8, column=1)
    ent_count = Entry(MidAddNew, textvariable=COUNT, font=('arial', 15), width=15)
    ent_count.grid(row=11, column=1)
    chk_storage = Checkbutton(MidAddNew, variable=STORAGE, onvalue="Yes", offvalue="No", bg="#009ACD", highlightbackground="#202020")
    chk_storage.grid(row=12, column=1)
    chk_storage.config(bg = "#202020", width=15)
    btn_add = Button(MidAddNew, text="Save", font=('arial', 18), width=30, bg="#009ACD", highlightbackground="#202020", command=AddNew)
    btn_add.grid(row=13, columnspan=2, pady=20)

#def change_dropdown(*args):
    #print( BUSINESS.get() )

#BUSINESS.trace('w', change_dropdown)

def NewSku():
    Database()
    if not isinstance(COUNT.get(), int):
        messagebox.showerror('Incorrect info', 'Please verify count is an integer')
    elif TYPE.get() == "" or MODEL.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `parts` WHERE `type` COLLATE NOCASE = ? AND 'model' COLLATE NOCASE = ?", (TYPE.get(), MODEL.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Part Exists', 'Part already exists in inventory', icon="info")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
        else:

            cursor.execute("INSERT INTO `parts` (type, model, count) VALUES(?, ?, ?)", (str(TYPE.get()), str(MODEL.get()), int(COUNT.get())))
            conn.commit()
            Log('Created Part', MODEL.get(), "")
            TYPE.set("")
            MODEL.set("")
            COUNT.set(0)
            messagebox.showinfo('Created Part', 'Successfully created new Part', icon="info")
            ResetSku()
            skuForm.withdraw()
        conn.close()

def CancelSku():
    TYPE.set("")
    MODEL.set("")
    COUNT.set(0)
    skuForm.withdraw()

def AddNew():
    if CURRENTBUS.get() == "Parts":
        AddNewParts()
    if CURRENTBUS.get() == "BG4":
        AddNewTer()
    if CURRENTBUS.get() == "BG5":
        AddNewTri()
    if CURRENTBUS.get() == "BG3":
        AddNewPie()
    if CURRENTBUS.get() == "BG2":
        AddNewAmp()
    if CURRENTBUS.get() == "Seed":
        AddNewSeed()


def AddNewParts():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `Parts` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'Parts' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetParts()

def AddNewPie():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `piesiri` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'piesiri' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetPie()

def AddNewTer():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `BG4` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'BG4' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetTer()

def AddNewTri():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `BG5` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'BG5' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetTri()

def AddNewAmp():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `amp` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'amp' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetAmp()

def AddNewSeed():
    Database()
    if BUILDING.get() == "" or ROOMNUMBER.get() == "" or LOCATION.get() == "" or BUSINESS.get() == "":
        messagebox.showerror('Missing Info', 'Please add missing information.', icon="error")
    else:
        cursor.execute("SELECT * FROM `seed` WHERE `building` COLLATE NOCASE = ? AND `roomnumber` COLLATE NOCASE = ? AND `location` COLLATE NOCASE = ?", (BUILDING.get(), ROOMNUMBER.get(), LOCATION.get()))
        if cursor.fetchone() is not None:
            messagebox.showerror('Location in use', 'Location is already in use')
            BUILDING.set("")
            LOCATION.set("")
            ROOMNUMBER.set("")
        else:
            cursor.execute("INSERT INTO 'seed' (building, roomnumber, location, business, vendor, partdesc, partnum, category, subcategory, count, storage) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(BUILDING.get()), int(ROOMNUMBER.get()), str(LOCATION.get()), str(BUSINESS.get()), str(VENDOR.get()), str(PARTDESC.get()), str(PARTNUM.get()), str(CATEGORY.get()), str(SUBCATEGORY.get()), int(COUNT.get()), str(STORAGE.get())))
            conn.commit()
            addlocation = (str(BUILDING.get()) + "//" + str(ROOMNUMBER.get()) + "//" + str(LOCATION.get()))
            Log('Added part', PARTDESC.get(), addlocation)
            SendEmail('Added part', PARTDESC.get(), addlocation, str(BUSINESS.get()))
            BUILDING.set("")
            ROOMNUMBER.set("")
            LOCATION.set("")
            BUSINESS.set("")
            VENDOR.set("")
            PARTDESC.set("")
            PARTNUM.set("")
            CATEGORY.set("")
            SUBCATEGORY.set("")
            COUNT.set("")
            STORAGE.set("")
            messagebox.showinfo('Part Added','Successfully added part to inventory.', icon="info")
            addnewform.withdraw()
    conn.close()
    ResetSeed()

def ShowParts2():
    global partsform
    SEARCH2.set("")
    partsform = Toplevel()
    partsform.title("HelpDesk Inventory/Parts")
    width = 1200
    height = 800
    scree_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    partsform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    partsform.resizable(1, 1)
    ViewParts()

def ShowLogs():
    global logform
    logform = Toplevel()
    logform.title("HelpDesk Inventory/View Log")
    width = 1200
    height = 800
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    logform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    logform.resizable(1, 1)
    ViewLogs()

def ViewParts():
    global tree4
    TopViewForm = Frame(partsform, width=400, bd=1, relief=SOLID)
    TopViewForm.pack(side=TOP, fill=X)
    TopViewForm.config(bg="#202020")
    LeftViewForm = Frame(partsform, width=400)
    LeftViewForm.pack(side=LEFT, fill=Y)
    LeftViewForm.config(bg="#202020")
    MidViewForm = Frame(partsform, width=400)
    MidViewForm.pack(side=RIGHT)
    MidViewForm.config(bg="#202020")
    lbl_text = Label(TopViewForm, text="Select Part", font=('arial', 18), width=400, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    lbl_txtsearch = Label(LeftViewForm, text="Filter", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_txtsearch.pack(side=TOP, anchor='center')
    search = Entry(LeftViewForm, textvariable=SEARCH2, font=('arial', 15), width=10, highlightbackground="#202020")
    search.pack(side=TOP,  padx=10, fill=X)
    btn_clearfilter = Button(LeftViewForm, text="Clear Filter", highlightbackground="#202020", command=ClearSkuFilter)
    btn_clearfilter.pack(side=TOP, padx=10, pady=10, fill=X)
    lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_seperate.pack(side=TOP, anchor='center')
    btn_add = Button(LeftViewForm, text="Add Part To Inventory", highlightbackground="#202020", command=CheckAddNew)
    btn_add.pack(side=TOP, padx=10, pady=10, fill=X)
    btn_sku = Button(LeftViewForm, text='Create new SKU', highlightbackground="#202020", command=ShowSku)
    btn_sku.pack(side=TOP, padx=10, pady=10, fill=X)
    scrollbarx = Scrollbar(MidViewForm, orient=HORIZONTAL)
    scrollbary = Scrollbar(MidViewForm, orient=VERTICAL)
    tree4 = ttk.Treeview(MidViewForm, columns=("part_id", "vendor", "partdesc", "partnum", "category", "subcategory"), selectmode="extended", height=100, yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
    ttk.Style().configure("Treeview", background="#CCBFB7", foreground="#000000", fieldbackground="#CCBFB7")
    tree4['show'] = 'headings'
    scrollbary.config(command=tree4.yview)
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree4.xview)
    scrollbarx.pack(side=BOTTOM, fill=X)
    tree4.heading('part_id', text="Part ID", anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'part_id', False))
    tree4.heading('vendor', text="Vendor",anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'vendor', False))
    tree4.heading('partdesc', text="Part Description",anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'partdesc', False))
    tree4.heading('partnum', text="Part Number", anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'partnum', False))
    tree4.heading('category', text="Category", anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'category', False))
    tree4.heading('subcategory', text="Sub-Category", anchor='center', command=lambda: \
                    treeview_sort_column(tree4, 'subcategory', False))
    tree4.column('#1', stretch=NO, minwidth=40, width=60)
    tree4.column('#2', stretch=NO, minwidth=40, width=200)
    tree4.column('#3', stretch=NO, minwidth=40, width=420)
    tree4.column('#4', stretch=NO, minwidth=40, width=300)
    tree4.column('#5', stretch=NO, minwidth=40, width=300)
    tree4.column('#6', stretch=NO, minwidth=40, width=300)
    tree4.pack()
    DisplayParts()



def filter_search1(*args):
    if CURRENTBUS.get() == "Parts":
        SearchParts()
    elif CURRENTBUS.get() == "BG3":
        SearchPie()
    elif CURRENTBUS.get() == "BG4":
        SearchTer()
    elif CURRENTBUS.get() == "BG5":
        SearchTri()
    elif CURRENTBUS.get() == "BG2":
        SearchAmp()
    elif CURRENTBUS.get() == "Seed":
        SearchSeed()

SEARCH.trace('w', filter_search1)

def filter_search2(*args):
    SearchByVendor()

SEARCH2.trace('w', filter_search2)

def CheckAddNew():
    if not tree4.selection():
       print("ERROR")
    else:
        partsform.withdraw()
        curItem = tree4.focus()
        contents =(tree4.item(curItem))
        selecteditem = contents['values']
        PARTID.set(selecteditem[0])
        VENDOR.set(selecteditem[1])
        PARTDESC.set(selecteditem[2])
        PARTNUM.set(selecteditem[3])
        CATEGORY.set(selecteditem[4])
        SUBCATEGORY.set(selecteditem[5])
        ShowAddNew()

def ViewLogs():
    global tree3
    TopViewForm = Frame(logform, width=400, bd=1, relief=SOLID)
    TopViewForm.pack(side=TOP, fill=X)
    TopViewForm.config(bg="#202020")
    LeftViewForm = Frame(logform, width=400)
    LeftViewForm.pack(side=LEFT, fill=Y)
    LeftViewForm.config(bg="#202020")
    MidViewForm = Frame(logform, width=400)
    MidViewForm.pack(side=RIGHT)
    MidViewForm.config(bg="#202020")
    lbl_text = Label(TopViewForm, text="View Log", font=('arial', 18), width=400, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    lbl_txtsearch = Label(LeftViewForm, text="Filter", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_txtsearch.pack(side=TOP, anchor='center')
    search = Entry(LeftViewForm, textvariable=SEARCH3, font=('arial', 15), width=10, highlightbackground="#202020")
    search.pack(side=TOP,  padx=10, fill=X)
    btn_clearfilter = Button(LeftViewForm, text="Clear Filter", highlightbackground="#202020", command=ClearLogFilter)
    btn_clearfilter.pack(side=TOP, anchor='center', pady=10)
    lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_seperate.pack(side=TOP, anchor='center')
    btn_clearlog = Button(LeftViewForm, text="Clear Log", highlightbackground="#202020", command=ClearLog)
    btn_clearlog.pack(side=TOP, padx=10, pady=10, fill=X)
    btn_exportlog = Button(LeftViewForm, text="Export log to CSV", highlightbackground="#202020", command=ExportLog)
    btn_exportlog.pack(side=TOP, padx=10, pady=10, fill=X)
    lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_seperate.pack(side=TOP, anchor='center')
    #btn_quarteraudit = Button(LeftViewForm, text="Quarter Audit", highlightbackground="#202020", command=QuarterAudit)
    #btn_quarteraudit.pack(side=TOP, padx=10, pady=10, fill=X)
    scrollbarx = Scrollbar(MidViewForm, orient=HORIZONTAL)
    scrollbary = Scrollbar(MidViewForm, orient=VERTICAL)
    tree3 = ttk.Treeview(MidViewForm, columns=("Log_Id", "Username", "Action", "Title", "Extra", "Timestamp"), selectmode="extended", height=100, yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
    ttk.Style().configure("Treeview", background="#CCBFB7", foreground="#000000", fieldbackground="#CCBFB7")
    tree3['show'] = 'headings'
    scrollbary.config(command=tree3.yview)
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree3.xview)
    scrollbarx.pack(side=BOTTOM, fill=X)
    tree3.heading('Log_Id', text="Log ID", anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Log_Id', False))
    tree3.heading('Username', text="User Name",anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Username', False))
    tree3.heading('Action', text="Action",anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Action', False))
    tree3.heading('Title', text="Title", anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Title', False))
    tree3.heading('Extra', text="Extra", anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Extra', False))
    tree3.heading('Timestamp', text="Time Stamp", anchor='center', command=lambda: \
                    treeview_sort_column(tree3, 'Timestamp', False))
    tree3.column('#1', stretch=NO, minwidth=40, width=60)
    tree3.column('#2', stretch=NO, minwidth=40, width=200)
    tree3.column('#3', stretch=NO, minwidth=40, width=300)
    tree3.column('#4', stretch=NO, minwidth=40, width=420)
    tree3.column('#5', stretch=NO, minwidth=40, width=300)
    tree3.column('#6', stretch=NO, minwidth=40, width=300)
    tree3.pack()
    DisplayLog()

def filter_search3(*args):
    SearchbyName()

SEARCH3.trace('w', filter_search3)

def LogSearch():
    if SEARCHFIELD.get() == "User Name":
        SearchbyName()
    elif SEARCHFIELD.get() == "Action":
        SearchbyAction()
    elif SEARCHFIELD.get() == "Title":
        SearchbyTitle()
    elif SEARCHFIELD.get() == "Time Stamp":
        SearchbyTimestamp()

def PartsSearch():
    if SEARCHFIELD2.get() == "Vendor":
        SearchByVendor()
    elif SEARCHFIELD2.get() == "Part Description":
        SearchByPartDesc()
    elif SEARCHFIELD2.get() == "Part Number":
        SearchByPartNum()
    elif SEARCHFIELD2.get() == "Category":
        SearchByCategory()
    elif SEARCHFIELD2.get() == "Sub-Category":
        SearchBySubcat()

def FullAudit():
    Database()
    cursor.execute("SELECT item_id FROM 'item'")
    fetch = cursor.fetchone()

    if fetch != None:
        cursor.execute("SELECT * FROM 'item'")
        fetch = cursor.fetchall()
        ts = time.time()
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        auditpath = path + "/Audit/"
        if not os.path.exists(auditpath):
            os.makedirs(auditpath)
        audittitle = auditpath + "FullAudit - " + timestamp + ".csv"
        headers = [("Item ID", "Building", "Room Number", "Location", "Business Group", "Vendor", "Part Description", "Part Number", "Category", "Sub-Category", "Count", "Storage")]
        data = headers + fetch
        with open(audittitle, "wb") as f:
            writer = csv.writer(f)
            writer.writerows(data)
        messagebox.showinfo('Full Audit','Full audit successfully exported.', icon="info")
    else:
        messagebox.showerror('Error','No items to audit', icon="error")
    cursor.close()
    conn.close()

def ViewForm():
    global tree
    TopViewForm = Frame(viewform, width=400, bd=1, relief=SOLID)
    TopViewForm.pack(side=TOP, fill=X)
    TopViewForm.config(bg="#202020")
    LeftViewForm = Frame(viewform, width=400)
    LeftViewForm.pack(side=LEFT, fill=Y)
    LeftViewForm.config(bg="#202020")
    MidViewForm = Frame(viewform, width=400)
    MidViewForm.pack(side=RIGHT)
    MidViewForm.config(bg="#202020")
    inventory_name = "Inventory"
    lbl_text = Label(TopViewForm, text=inventory_name, font=('arial', 18), width=400, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    lbl_txtsearch = Label(LeftViewForm, text="Filter", font=('arial', 15), fg="#BDBDBD", bg="#202020")
    lbl_txtsearch.pack(side=TOP, anchor='center')
    search = Entry(LeftViewForm, textvariable=SEARCH, font=('arial', 15), width=10, highlightbackground="#202020")
    search.pack(side=TOP,  padx=10, fill=X)
    btn_clear = Button(LeftViewForm, text="Clear Filter", highlightbackground="#202020", command=ClearFilter)
    btn_clear.pack(side=TOP, padx=10, pady=10, fill=X)
    if privlevel == 1 or privlevel == 2:
        lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
        lbl_seperate.pack(side=TOP, anchor='center')
        btn_inout = Button(LeftViewForm, text="Check In/Out", highlightbackground="#202020", command=ShowCheckInOutSelect)
        btn_inout.pack(side=TOP, padx=10, pady=10, fill=X)
    if privlevel == 1:
        lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
        lbl_seperate.pack(side=TOP, anchor='center')
        btn_add = Button(LeftViewForm, text="Add Part", highlightbackground="#202020", command=ShowSku)
        btn_add.pack(side=TOP, padx=10, pady=10, fill=X)
        btn_edit = Button(LeftViewForm, text="Edit Part", highlightbackground="#202020", command=EditSelect)
        btn_edit.pack(side=TOP, padx=10, pady=10, fill=X)
        btn_delete = Button(LeftViewForm, text="Delete Part", highlightbackground="#202020", command=DeleteParts)
        btn_delete.pack(side=TOP, padx=10, pady=10, fill=X)
        lbl_seperate = Label(LeftViewForm, text="----------------------------------------", font=('arial', 15), fg="#BDBDBD", bg="#202020")
        lbl_seperate.pack(side=TOP, anchor='center')
    scrollbarx = Scrollbar(MidViewForm, orient=HORIZONTAL)
    scrollbary = Scrollbar(MidViewForm, orient=VERTICAL)
    tree = ttk.Treeview(MidViewForm, columns=("item_id", "type", "model", "count"), selectmode="extended", height=100, yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
    ttk.Style().configure("Treeview", background="#CCBFB7", foreground="#000000", fieldbackground="#CCBFB7")
    tree['show'] = 'headings'
    scrollbary.config(command=tree.yview)
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree.xview)
    scrollbarx.pack(side=BOTTOM, fill=X)
    tree.heading('item_id', text="Item ID", anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'item_id', False))
    tree.heading('type', text="Type",anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'type', False))
    tree.heading('model', text="Model",anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'subtype', False))
    tree.heading('count', text="Count",anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'name', False))
    tree.column('#1', stretch=NO, minwidth=40, width=80)
    tree.column('#2', stretch=NO, minwidth=40, width=170)
    tree.column('#3', stretch=NO, minwidth=40, width=170)
    tree.column('#4', stretch=NO, minwidth=40, width=80)
    tree.pack()

def ClearFilter():
    if CURRENTBUS.get() == "Parts":
        ResetParts()

def WhichSearch():
    if SEARCHFIELD.get() == "Building":
        Search3()
    elif SEARCHFIELD.get() == "Part Description":
        Search()
    elif SEARCHFIELD.get() == "Business":
        Search2()
    elif SEARCHFIELD.get() == "Room Number":
        Search4()
    elif SEARCHFIELD.get() == "Location":
        Search5()
    elif SEARCHFIELD.get() == "Vendor":
        Search6()
    elif SEARCHFIELD.get() == "Part Number":
        Search8()
    elif SEARCHFIELD.get() == "Category":
        Search9()
    elif SEARCHFIELD.get() == "Sub-Category":
        Search10()

def Reset2():
    tree2.delete(*tree2.get_children())
    DisplayUsers()

def Clear():
    SEARCHFIELD.set("")
    Reset()

def Clear2():
    SEARCHFIELD.set("")
    Reset3()

def Clear3():
    SEARCHFIELD2.set("")
    Reset4()

def treeview_sort_column(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    l.sort(reverse=reverse)

    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)

        tv.heading(col, command=lambda: \
                    treeview_sort_column(tv, col, not reverse))

def ConfigurationForm():
    global tree2
    configurationform.config(bg="#202020")
    TopViewForm = Frame(configurationform, width=400, bd=1, relief=SOLID)
    TopViewForm.pack(side=TOP, fill=X)
    LeftViewForm = Frame(configurationform, width=400, bg="#202020")
    LeftViewForm.pack(side=LEFT, fill=Y)
    MidViewForm = Frame(configurationform, width=400)
    MidViewForm.pack(side=RIGHT)
    MidViewForm.config(bg="#202020")
    lbl_text = Label(TopViewForm, text="Users", font=('arial', 18), width=400, fg="#BDBDBD", bg="#202020")
    lbl_text.pack(fill=X)
    btn_changepass = Button(LeftViewForm, text="Change User Password", highlightbackground="#202020", command=SelectUserPass)
    btn_changepass.pack(side=TOP, padx=10, pady=10, fill=X)
    btn_addnewuser = Button(LeftViewForm, text="Add New User", highlightbackground="#202020", command=ShowAddNewUser)
    btn_addnewuser.pack(side=TOP, padx=10, pady=10, fill=X)
    btn_deluser = Button(LeftViewForm, text="Delete User", highlightbackground="#202020", command=DelUser)
    btn_deluser.pack(side=TOP, padx=10, pady=10, fill=X)
    scrollbarx = Scrollbar(MidViewForm, orient=HORIZONTAL)
    scrollbary = Scrollbar(MidViewForm, orient=VERTICAL)
    tree2 = ttk.Treeview(MidViewForm, columns=("User_Id", "username", "privlevel", "belonging"), selectmode="extended", height=100, yscrollcommand=scrollbary.set, xscrollcommand=scrollbarx.set)
    ttk.Style().configure("Treeview", background="#CCBFB7", foreground="#000000", fieldbackground="#CCBFB7")
    tree2['show'] = 'headings'
    scrollbary.config(command=tree2.yview, bg="#202020")
    scrollbary.pack(side=RIGHT, fill=Y)
    scrollbarx.config(command=tree2.xview, bg="#202020")
    scrollbarx.pack(side=BOTTOM, fill=X)
    tree2.heading('User_Id', text="User ID", anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'User_Id', False))
    tree2.heading('username', text="User Name",anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'username', False))
    tree2.heading('privlevel', text="Privilege",anchor='center', command=lambda: \
                    treeview_sort_column(tree2, 'privlevel', False))
    tree2.column('#1', stretch=NO, minwidth=40, width=60)
    tree2.column('#2', stretch=NO, minwidth=40, width=170)
    tree2.column('#3', stretch=NO, minwidth=40, width=60)
    tree2.pack()
    DisplayUsers()

def DisplayUsers():
    Database()
    cursor.execute("SELECT user_id, username, privlevel FROM 'users' ORDER BY 'username' COLLATE NOCASE DESC")
    fetch = cursor.fetchall()
    for data in fetch:
        tree2.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataParts():
    Database()
    cursor.execute("SELECT * FROM `Parts`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataPie():
    Database()
    cursor.execute("SELECT * FROM `piesiri`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataTer():
    Database()
    cursor.execute("SELECT * FROM `BG4`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataTri():
    Database()
    cursor.execute("SELECT * FROM `BG5`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataSeed():
    Database()
    cursor.execute("SELECT * FROM `seed`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayDataAmp():
    Database()
    cursor.execute("SELECT * FROM `amp`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayLog():
    Database()
    cursor.execute("SELECT * FROM `log`")
    fetch = cursor.fetchall()
    for data in fetch:
        tree3.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def DisplayParts():
    Database()
    cursor.execute("SELECT * FROM 'parts'")
    fetch = cursor.fetchall()
    for data in fetch:
        tree.insert('', 'end', values=(data))
    cursor.close()
    conn.close()

def ExportLog():
    Database()
    cursor.execute("SELECT timestamp FROM 'log'")
    fetch = cursor.fetchone()
    if fetch != None:
        cursor.execute("SELECT * FROM 'log'")
        fetch = cursor.fetchall()
        ts = time.time()
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        logpath = path + "/Logs/"
        if not os.path.exists(logpath):
            os.makedirs(logpath)
        logtitle = logpath + "Log - " + timestamp + ".csv"
        with open(logtitle, "wb") as f:
            writer = csv.writer(f)
            writer.writerows(fetch)
        messagebox.showinfo('Log Export','Log successfully exported.', icon="info")
    else:
        messagebox.showerror('Error','Log is empty', icon="error")
    cursor.close()
    conn.close()

def SearchbyName():
    if SEARCH3.get() != "":
        tree3.delete(*tree3.get_children())
        Database()
        cursor.execute("SELECT * FROM `log` WHERE `username` LIKE ? OR `action` LIKE ? OR `title` LIKE ? OR `extra` LIKE ? OR `timestamp` LIKE ?", ('%'+str(SEARCH3.get())+'%', '%'+str(SEARCH3.get())+'%', '%'+str(SEARCH3.get())+'%', '%'+str(SEARCH3.get())+'%', '%'+str(SEARCH3.get())+'%'))
        fetch = cursor.fetchall()
        for data in fetch:
            tree3.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchByVendor():
    if SEARCH2.get() != "":
        tree4.delete(*tree4.get_children())
        Database()
        cursor.execute("SELECT * FROM `parts` WHERE `vendor` LIKE ? OR `partdesc` LIKE ? OR `partnum` LIKE ? OR `category` LIKE ? OR `subcategory` LIKE ?", ('%'+str(SEARCH2.get())+'%', '%'+str(SEARCH2.get())+'%', '%'+str(SEARCH2.get())+'%', '%'+str(SEARCH2.get())+'%', '%'+str(SEARCH2.get())+'%'))
        fetch = cursor.fetchall()
        for data in fetch:
            tree4.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchByPartDesc():
    if SEARCH2.get() != "":
        tree4.delete(*tree4.get_children())
        Database()
        cursor.execute("SELECT * FROM `parts` WHERE `partdesc` LIKE ?", ('%'+str(SEARCH2.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree4.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchByPartNum():
    if SEARCH2.get() != "":
        tree4.delete(*tree4.get_children())
        Database()
        cursor.execute("SELECT * FROM `parts` WHERE `partnum` LIKE ?", ('%'+str(SEARCH2.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree4.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchByCategory():
    if SEARCH2.get() != "":
        tree4.delete(*tree4.get_children())
        Database()
        cursor.execute("SELECT * FROM `parts` WHERE `category` LIKE ?", ('%'+str(SEARCH2.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree4.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchBySubcat():
    if SEARCH2.get() != "":
        tree4.delete(*tree4.get_children())
        Database()
        cursor.execute("SELECT * FROM `parts` WHERE `subcategory` LIKE ?", ('%'+str(SEARCH2.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree4.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchbyAction():
    if SEARCH.get() != "":
        tree3.delete(*tree3.get_children())
        Database()
        cursor.execute("SELECT * FROM `log` WHERE `action` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree3.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchbyTimestamp():
    if SEARCH.get() != "":
        tree3.delete(*tree3.get_children())
        Database()
        cursor.execute("SELECT * FROM `log` WHERE `timestamp` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree3.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchbyTitle():
    if SEARCH.get() != "":
        tree3.delete(*tree3.get_children())
        Database()
        cursor.execute("SELECT * FROM `log` WHERE `title` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree3.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchAmp():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `amp` WHERE `business` = ? AND `partdesc` LIKE ? OR `vendor` LIKE ?", ('Parts', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%'))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchParts():
     if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `Parts` WHERE `building` LIKE ? OR `roomnumber` LIKE ? OR `location` LIKE ? OR `vendor` LIKE ? OR `partdesc` LIKE ? OR `partnum` LIKE ? OR `category` LIKE ? or `subcategory` LIKE ?", ('%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%', '%'+str(SEARCH.get())+'%'))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchPie():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `piesiri` WHERE `building` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchTer():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `BG5` WHERE `roomnumber` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchTri():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `BG4` WHERE `location` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def SearchSeed():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `seed` WHERE `vendor` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def Search8():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `item` WHERE `partnum` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def Search9():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `item` WHERE `category` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def Search10():
    if SEARCH.get() != "":
        tree.delete(*tree.get_children())
        Database()
        cursor.execute("SELECT * FROM `item` WHERE `subcategory` LIKE ?", ('%'+str(SEARCH.get())+'%',))
        fetch = cursor.fetchall()
        for data in fetch:
            tree.insert('', 'end', values=(data))
        cursor.close()
        conn.close()

def ClearSkuFilter():
    tree4.delete(*tree4.get_children())
    DisplayParts()

def ClearLogFilter():
    tree3.delete(*tree3.get_children())
    DisplayLog()

def ResetSku():
    tree.delete(*tree.get_children())
    DisplayParts()

def ResetParts():
    tree.delete(*tree.get_children())
    DisplayDataParts()
    SEARCH.set("")

def ResetPie():
    tree.delete(*tree.get_children())
    DisplayDataPie()
    SEARCH.set("")

def ResetTri():
    tree.delete(*tree.get_children())
    DisplayDataTri()
    SEARCH.set("")

def ResetTer():
    tree.delete(*tree.get_children())
    DisplayDataTer()
    SEARCH.set("")

def ResetAmp():
    tree.delete(*tree.get_children())
    DisplayDataAmp()
    SEARCH.set("")

def ResetSeed():
    tree.delete(*tree.get_children())
    DisplayDataSeed()
    SEARCH.set("")

def ClearLog():
    result = messagebox.askquestion('HelpDesk Log', 'Are you sure you want to clear the log?', icon="warning")
    if result == 'yes':
        Database()
        cursor.execute("DELETE FROM 'log'")
        conn.commit()
        cursor.close()
        conn.close()
        Reset3()

def DeleteParts():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `Parts` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetParts()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))

def DeletePie():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `piesiri` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetPie()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))

def DeleteTer():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `BG4` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetTer()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))

def DeleteTri():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `BG5` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetTri()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))

def DeleteAmp():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `amp` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetAmp()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))

def DeleteSeed():
    if not tree.selection():
       print("ERROR")
    else:
        result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to remove this part?', icon="warning")
        if result == 'yes':
            curItem = tree.focus()
            contents =(tree.item(curItem))
            selecteditem = contents['values']
            tree.delete(curItem)
            Database()
            cursor.execute("DELETE FROM `seed` WHERE `item_id` = %d" % selecteditem[0])
            conn.commit()
            cursor.close()
            ResetSeed()
            setLocation = str(selecteditem[1]) + "//" + str(selecteditem[2]) + "//" + str(selecteditem[3])
            Log('Removed Part', selecteditem[6], setLocation)
            SendEmail('Removed part', selecteditem[6], setLocation, str(selecteditem[4]))



def DelUser():
    if not tree2.selection():
       print("ERROR")
    curItem2 = tree2.focus()
    contents2 = (tree2.item(curItem2))
    selecteditem2 = contents2['values']
    if selecteditem2[1] == 'admin':
        messagebox.showerror('HelpDesk Inventory', 'Unable to delete admin account', icon="warning")
    elif selecteditem2[1] == user_name:
        messagebox.showerror('HelpDesk Inventory', 'Unable to delete active user', icon="warning")
    else:
        result2 = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to delete this user?', icon="warning")
        tree2.delete(curItem2)
        Database()
        cursor.execute("DELETE FROM `users` WHERE `user_id` = %d" % selecteditem2[0])
        conn.commit()
        cursor.close()
        conn.close()
        privilege = 'Privilege ' + str(selecteditem2[2])
        Log('Deleted User', selecteditem2[1], privilege)

def ShowParts():
    global viewform
    viewform = Toplevel()
    viewform.title("HelpDesk Inventory/View Inventory")
    width = 820
    height = 800
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    viewform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    viewform.resizable(0, 0)
    ViewForm()

def ShowUserConfiguration():
    global configurationform
    configurationform = Toplevel()
    configurationform.title("Users List")
    width =500
    height = 600
    screen_width = Home.winfo_screenwidth()
    screen_height = Home.winfo_screenheight()
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    configurationform.geometry("%dx%d+%d+%d" % (width, height, x, y))
    configurationform.resizable(0, 0)
    ConfigurationForm()

def Log(action, title, extra):
    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    Database()
    cursor.execute("INSERT INTO `log` (username, action, title, extra, timestamp) VALUES(?, ?, ?, ?, ?)", (str(user_name), str(action), str(title), str(extra), str(timestamp)))
    conn.commit()
    cursor.close()
    conn.close()

def SendEmail(action, title, extra, business):
    ts = time.time()
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    myMessage = ("User: " + str(user_name) + "\n" + "Action: " + str(action) +"\n" + "Part: " + str(title) + "\n" + "Location: " + str(extra) + "\n" + "Business: " + str(business) + "\n" + "Time: " + str(timestamp))
    sendemail(from_addr    = 'To email address',
          to_addr_list = ['from email address'],
          cc_addr_list = [''],
          subject      = 'Racks update',
          message      = myMessage,
          login        = 'email login',
          password     = 'email password')

def sendemail(from_addr, to_addr_list, cc_addr_list,
              subject, message,
              login, password,
              smtpserver='email server'):
    header  = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Cc: %s\n' % ','.join(cc_addr_list)
    header += 'Subject: %s\n\n' % subject
    message = header + message

    server = smtplib.SMTP(smtpserver)
    server.starttls()
    server.login(login,password)
    problems = server.sendmail(from_addr, to_addr_list, message)
    server.quit()
    return problems

def Logout():
    result = messagebox.askquestion('HelpDesk Inventory', 'Are you sure you want to logout?', icon="warning")
    if result == 'yes':
        user_id = ""
        root.deiconify()
        Home.destroy()

def Login(event=None):
    global user_id
    global user_name
    global privlevel
    global belonging
    Database()
    if USERNAME.get() == "" or PASSWORD.get() == "":
        lbl_result.config(text="Please complete missing field!", fg="red")
    else:
        hash = pbkdf2_sha256.hash(PASSWORD.get(), rounds=2000, salt_size=16)
        cursor.execute("SELECT * FROM `users` WHERE `username` COLLATE NOCASE = ?", (USERNAME.get(),))
        fetch = cursor.fetchone()
        if fetch is not None:
            if pbkdf2_sha256.verify(PASSWORD.get(), fetch[2]):
                cursor.execute("SELECT * FROM `users` WHERE `username` COLLATE NOCASE = ?", (USERNAME.get(),))
                data = cursor.fetchone()
                user_id = data[0]
                user_name = USERNAME.get()
                privlevel = data[3]
                USERNAME.set("")
                PASSWORD.set("")
                lbl_result.config(text="")
                Log('Logged In', '', '')
                ShowHome()
            else:
                lbl_result.config(text="Invalid username or password", fg="red")
                USERNAME.set("")
                PASSWORD.set("")
                PRIVLEVEL.set("")
        else:
            lbl_result.config(text="Username not found", fg="red")
            USERNAME.set("")
            PASSWORD.set("")
            PRIVLEVEL.set("")
    conn.close()

def ShowHome():
    root.withdraw()
    Home()
    loginform.destroy()


#========================================MENUBAR WIDGETS==================================
menubar = Menu(root)
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Login", command=ShowLoginForm)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=Exit)
menubar.add_cascade(label="File", menu=filemenu)
root.config(menu=menubar)

#========================================FRAME============================================
Title = Frame(root, bd=1, relief=SOLID)
Title.pack(pady=10)

#========================================LABEL WIDGET=====================================
lbl_display = Label(Title, text="HelpDesk Inventory", font=('arial', 35), bg="#202020", fg="#BDBDBD")
lbl_display.pack()
btn_newlogin = Button(root, text="Login", font=('arial', 18), width=10, pady=10, command=ShowLoginForm, highlightbackground="#202020")
btn_newlogin.pack(pady=20)
btn_exit = Button(root, text="Exit", font=('arial', 18), width=10, pady=10, command=Exit, highlightbackground="#202020")
btn_exit.pack()
lbl_email = Label(root, text="v1.1 by email@gmail.com", font=('arial', 10), pady=60, fg="#BDBDBD", bg="#202020")
lbl_email.pack()


#========================================INITIALIZATION===================================
if __name__ == '__main__':
    root.mainloop()
