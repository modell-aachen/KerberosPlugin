#---+ Extensions
#---++ KerberosPlugin
# Enables Kerberos authentication

# **STRING 100**
# The Kerberos realm used for authentication.
$Foswiki::cfg{Plugins}{KerberosPlugin}{Realm} = '';

# **STRING**
# A comma separated list of usernames which are forced to authenticated by username and password
$Foswiki::cfg{Plugins}{KerberosPlugin}{NonKerberosUsers} = '';

# **BOOLEAN**
# Requires package LdapContrib
$Foswiki::cfg{Plugins}{KerberosPlugin}{UseLdap} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{PreventBrowserRememberingPassword} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{DontUseKerberosForAdminUser} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{StripRealmFromLoginName} = 0;
