#---+ Extensions
#---++ KerberosPlugin
# Enables Kerberos authentication

# **STRING 100**
# The Kerberos realm used for authentication.
$Foswiki::cfg{Plugins}{KerberosPlugin}{Realm} = '';

# **BOOLEAN**
# Requires package LdapContrib
$Foswiki::cfg{Plugins}{KerberosPlugin}{UseLdap} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{PreventBrowserRememberingPassword} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{DontUseKerberosForAdminUser} = 0;

# **BOOLEAN**
$Foswiki::cfg{Plugins}{KerberosPlugin}{StripRealmFromLoginName} = 0;
