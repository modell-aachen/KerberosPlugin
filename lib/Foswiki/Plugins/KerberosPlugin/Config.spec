#---+ Extensions
#---++ KerberosPlugin
# Enables Kerberos authentication

# **PERL**
# List of all domains and sub-domains.
$Foswiki::cfg{Plugins}{KerberosPlugin}{Realms} = {
    'ACME' => 'ACME.LOCAL',
    'SUB' => 'SUB.ACME.LOCAL'
};

# **STRING 100**
# The default realm used for authentication without specifying a prefix(NETBIOS domain name).
$Foswiki::cfg{Plugins}{KerberosPlugin}{DefaultRealm} = 'ACME';

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
