Authentication to OpenLDAP-database in Laravel 4

For config example see:
https://github.com/blindern/intern/blob/master/app/config/auth.php

This version is unstable, and has moved partly out of Laravel for now.
A working version (read only, no changes to users available)
can be retrieved from revision 02f34570b.

The reason behind this is that we are trying to abstract the LDAP-layer
away from Laravel on the project this is being used, to keep a seperate
user-API to easier being able to move away from LDAP later if wanted,
including letting other services use the same API. So instead of writing
new driver for Laravel and all the other projects using the same users-
database, only one place have to be updated.

See https://github.com/blindern/users-api
and https://github.com/blindern/intern