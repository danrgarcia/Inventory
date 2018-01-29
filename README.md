# Inventory
A Python GUI inventory system for managaging parts.

Inventory system allows for multiple business groups. Rather than a whole team having to move from system to system this allows a window for them to all of the parts in place. It then only relies on one or a small team of people to maintain the numerous other inventory systems allowing for break-fix techs to work faster.

When initially ran it will create a SQL database containing all necessary tables and columns. It will also create a default user of admin admin. Inventory system allows for admin to create users with 3 levels of privilege. Level 1 is admin and has full rights, level 2 is user and has the ability to check in and out quantities of parts, level 3 is a read only privilege. System also uses groups, Breakfix has access to see all business groups parts anyone else listed under one of these groups can only see their respective parts.

Working on adding some APIs so that the system can update the various other inventory systems the business groups use. For now each action is logged and an email is sent to the logistics rep to update the various inventory system.
