# Inventory
A Python GUI inventory system for managaging parts.

The code is not the cleanest but I did get a chance to learn alot about using hashing for passwords with a salt as well as SQLite and Tkinter experience. I enjoyed working on this project and had to remove a lot due to the company it was originally built for.

When initially ran it will create a SQL database containing all necessary tables and columns. It will also create a default user of admin admin. Inventory system allows for admin to create users with 3 levels of privilege. Level 1 is admin and has full rights, level 2 is user and has the ability to check in and out quantities of parts, level 3 is a read only privilege. System also uses groups, Breakfix has access to see all business groups parts anyone else listed under one of these groups can only see their respective parts.
