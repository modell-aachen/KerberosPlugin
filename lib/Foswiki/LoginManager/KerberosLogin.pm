package Foswiki::LoginManager::KerberosLogin;

use strict;
use Assert;

use utf8;
use Foswiki::LoginManager ();
use Foswiki::Contrib::LdapContrib ();
our @ISA = ( 'Foswiki::LoginManager' );

use Authen::Krb5::Simple;

sub new {
  my ( $class, $session ) = @_;
  my $self = $class->SUPER::new( $session );
  $session->enterContext( 'can_login' );

  if ( $Foswiki::cfg{Sessions}{ExpireCookiesAfter} ) {
    $session->enterContext( 'can_remember_login' );
  }

  if ( $Foswiki::cfg{Plugins}{KerberosPlugin}{PreventBrowserRememberingPassword} ) {
    $session->enterContext( 'no_auto_complete_login' );
  }

  $self->{UseLdap} = $Foswiki::cfg{Plugins}{KerberosPlugin}{UseLdap} || 0;
  $self->{DenyNonLdapUser} = $Foswiki::cfg{Plugins}{KerberosPlugin}{DenyNonLdapUser} || 0;
  eval {
    if ( $self->{UseLdap} ) {
      $self->{ldap} = Foswiki::Contrib::LdapContrib::getLdapContrib( $session );
    }
  };

  unless ( $@ ) {
    $self->{hasLdap} = 1;
  }

  Foswiki::registerTagHandler( 'LOGIN', \&_handleLogin );
  Foswiki::registerTagHandler( 'LOGOUT', \&_handleLogout );

  return $self;
}

sub _handleLogin {
  my $session = shift;
  my $self = $session->getLoginManager();
  return '' if $session->inContext( 'authenticated' );

  my $url = $self->loginUrl();
  return '' unless $url;
  return CGI::a( { href => $url }, '%MAKETEXT{"Login"}%' );
}

sub _handleLogout {
  my $session = shift;
  my $self = $session->getLoginManager();
  return '' unless $session->inContext( 'authenticated' );

  my $query = $session->{request};
  my $requestLocation = $query->{param}->{location}[0];

  my $url;
  if ( $requestLocation ) {
    if ( $requestLocation eq "/" ) {
      $url = $session->getScriptUrl( 0, 'view', $session->{webName}, $session->{topicName}, 'logout' => 1 );
    } else {
      my @parts = split( /\//, $requestLocation );
      # parts[1] = web, parts[2] = topic
      $url = $session->getScriptUrl( 0, 'view', $parts[1], $parts[2], 'logout' => 1 );
    }
  } else {
    my $web = $session->{prefs}->getPreference( 'BASEWEB' );
    my $topic = $session->{prefs}->getPreference( 'BASETOPIC' );
    $url = $session->getScriptUrl( 0, 'view', $web, $topic, 'logout' => 1 );
  }

  return '' unless $url;
  return CGI::a( { href => $url }, '%MAKETEXT{"Logout"}%' );
}

sub _packRequest {
  my ( $uri, $method, $action ) = @_;
  return '' unless $uri;
  if ( ref( $uri ) ) {
    my $r = $uri->{request};

    $uri    = $r->uri();
    $method = $r->method() || 'UNDEFINED';
    $action = $r->action();

    if ( $action eq "rest" ) {
      $action = "view";
      my $location = ( defined $r->{param}->{location} ? $r->{param}->{location}[0] : undef );
      if ( $location ) {
        $uri = $location;
      }
    }
  }

  return "$method,$action,$uri";
}

sub _unpackRequest {
  my $packed = shift || '';
  my ( $method, $action, $uri ) = split( ',', $packed, 3 );
  return ( $uri, $method, $action );
}

sub forceAuthentication {
  my $self    = shift;
  my $session = $self->{session};

  unless ( $session->inContext( 'authenticated' ) ) {
    my $query    = $session->{request};
    my $response = $session->{response};

    # Respond with a 401 with an appropriate WWW-Authenticate
    # that won't be snatched by the browser, but can be used
    # by JS to generate login info.
    $response->header(
      -status           => 200,
      -WWW_Authenticate => 'FoswikiBasic realm="'
      . ( $Foswiki::cfg{AuthRealm} || "" ) . '"'
    );

    $query->param(
      -name  => 'foswiki_origin',
      -value => _packRequest( $session )
    );

    # Throw back the login page with the 401
    $self->login( $query, $session );

    return 1;
  }

  return 0;
}

# zu 99% identisch zu Foswiki::LoginManager::loadSession..
# wird hier überschrieben, um einen (Apache)RemoteUser ignorieren zu können.
sub loadSession {
    my ( $self, $defaultUser, $pwchecker ) = @_;
    my $session = $self->{session};

    $defaultUser = $Foswiki::cfg{DefaultUserLogin}
      unless ( defined($defaultUser) );

    my $authUser;
    if ( $Foswiki::cfg{UseClientSessions}
        && !$session->inContext('command_line') )
    {

        $self->{_haveCookie} = $session->{request}->header('Cookie');

        # Item3568: CGI::Session from 4.0 already does the -d and creates the
        # sessions directory if it does not exist. For performance reasons we
        # only test for and create session file directory for older
        # CGI::Session
        my $sessionDir = "$Foswiki::cfg{WorkingDir}/tmp";
        if ( $Foswiki::LoginManager::Session::VERSION < 4.0 ) {
            unless (
                -d $sessionDir
                || (   mkdir( $Foswiki::cfg{WorkingDir} )
                    && mkdir($sessionDir) )
              )
            {
                die "Could not create $sessionDir for storing sessions";
            }
        }

        # force an appropriate umask
        my $oldUmask =
          umask(
            oct(777) - ( ( $Foswiki::cfg{Session}{filePermission} + 0 ) ) &
              oct(777) );

        # First, see if there is a cookied session, creating a new session
        # if necessary.
        if ( $Foswiki::cfg{Sessions}{MapIP2SID} ) {

            # map the end user IP address to a session ID
            my $sid = $self->_IP2SID();
            if ($sid) {
                $self->{_cgisession} = Foswiki::LoginManager::Session->new(
                    undef, $sid,
                    {
                        Directory => $sessionDir,
                        UMask     => $Foswiki::cfg{Session}{filePermission}
                    }
                );
            }
            else {

                # The IP address was not mapped; create a new session

                $self->{_cgisession} = Foswiki::LoginManager::Session->new(
                    undef, undef,
                    {
                        Directory => $sessionDir,
                        UMask     => $Foswiki::cfg{Session}{filePermission}
                    }
                );
                $self->_IP2SID( $self->{_cgisession}->id() );
            }
        }
        else {

            # IP mapping is off; use the request cookie
            $self->{_cgisession} = Foswiki::LoginManager::Session->new(
                undef,
                $session->{request},
                {
                    Directory => $sessionDir,
                    UMask     => $Foswiki::cfg{Session}{filePermission}
                }
            );
        }

        # restore old umask
        umask($oldUmask);

        die Foswiki::LoginManager::Session->errstr()
          unless $self->{_cgisession};

        # Get the authorised user stored in the session

        my $sessionUser = Foswiki::Sandbox::untaintUnchecked(
            $self->{_cgisession}->param('AUTHUSER') );

        # An admin user stored in the session can override the webserver
        # user; handy for sudo

        $authUser = $sessionUser
          if ( !defined($authUser)
            || $sessionUser && $sessionUser eq $Foswiki::cfg{AdminUserLogin} );
    }



    # Fix für SwitchableLogin
    my $sudoEnabled = $Foswiki::cfg{SwitchableLoginManagerContrib}{SudoEnabled} &&
      $Foswiki::cfg{SwitchableLoginManagerContrib}{SudoAuth} ne 'changeme!';
    my $sudo = $session->{request}->param('sudouser');
    my $sudoauth = $session->{request}->param('sudoauth');
    if ( $sudoEnabled && $sudo ) {
      $authUser = $self->getUser();
    }

    if ( !$authUser ) {
        # if we couldn't get the login manager or the http session to tell
        # us who the user is, check the username and password URI params.

        my $login = $session->{request}->param('username');
        my $pass  = $session->{request}->param('password');

        if ( !$login ) {

            # Nothing in the query params. Check query headers.
            my $auth = $session->{request}->http('X-Authorization');
            if ( defined $auth ) {
                if ( $auth =~ /^FoswikiBasic (.+)$/ ) {

                    # If the user agent wishes to send the userid "Aladdin"
                    # and password "open sesame", it would use the following
                    # header field:
                    # Authorization: Foswiki QWxhZGRpbjpvcGVuIHNlc2FtZQ==
                    require MIME::Base64;
                    my $cred = MIME::Base64::decode_base64($1);
                    if ( $cred =~ /:/ ) {
                        ( $login, $pass ) = split( ':', $cred, 2 );
                    }
                }    # TODO: implement FoswikiDigest here
            }

            # Wird der IE einmal aufgefordert einen Negotiation-Header zu schicken, wird
            # er diesen immer wieder mitschicken.
            # Die folgenden Zeilen dienen daher als Hotfix, um einen Kerberos-Logout zu ermöglichen.
            # Ist KRB_LOGOUT gesetzt, ignorieren wir den Apache-User.
            my $krbLoggedOut = Foswiki::Func::getSessionValue( "KRB_LOGOUT" );
            unless ( $krbLoggedOut ) {
              $authUser = $self->getUser( $self );
            }
        }

        if ( $login && defined $pass && $pwchecker ) {
            my $validation = $pwchecker->checkPassword( $login, $pass );
            unless ($validation) {
                my $res = $session->{response};
                my $err = "ERROR: (401) Can't login as $login";

                # Item1953: You might think that this is needed:
                #    $res->header( -type => 'text/html', -status => '401' );
                #    throw Foswiki::EngineException( 401, $err, $res );
                # but it would be wrong, because it would require the
                # exception to be handled before the session object is
                # properly initialised, which would cause an error.
                # Instead, we do this, and let the caller handle the error.
                undef $login;
            }
            $authUser = $login || $defaultUser;
        }
        else {

            # Last ditch attempt; if a user was passed in to this function,
            # then use it (it is normally {remoteUser} from the session
            # object)
            $authUser = $defaultUser unless $authUser;
        }
    }

    # We should have a user at this point; or $defaultUser if there
    # was no better information available.

    # is this a logout?
    if (   ( $authUser && $authUser ne $Foswiki::cfg{DefaultUserLogin} )
        && ( $session->{request} && $session->{request}->param('logout') ) )
    {
        # Wird der IE einmal aufgefordert einen Negotiation-Header zu schicken, wird
        # er diesen immer wieder mitschicken.
        # Die folgenden Zeilen dienen daher als Hotfix, um einen Kerberos-Logout zu ermöglichen.
        # Wir setzen die Session-Var KRB_LOGOUT, die signalisiert, dass der Apache User
        # ignoriert werden soll.
        Foswiki::Func::setSessionValue( "KRB_LOGOUT", "1" );

        # SMELL: is there any way to get evil data into the CGI session such
        # that this untaint is less than safe?
        my $sudoUser = Foswiki::Sandbox::untaintUnchecked(
            $self->{_cgisession}->param('SUDOFROMAUTHUSER') );

        if ($sudoUser) {
            $session->logger->log(
                {
                    level  => 'info',
                    action => 'sudo logout',
                    extra  => 'from ' . ( $authUser || '' ),
                    user   => $sudoUser
                }
            );
            $self->{_cgisession}->clear('SUDOFROMAUTHUSER');
            $authUser = $sudoUser;
        }
        else {
            $authUser =
              $self->redirectToLoggedOutUrl( $authUser, $defaultUser );
        }
    }
    $session->{request}->delete('logout');
    $self->userLoggedIn($authUser);

    if ( $self->{_cgisession} ) {
        $session->{prefs}->setInternalPreferences(
            SESSIONID  => $self->{_cgisession}->id(),
            SESSIONVAR => $CGI::Session::NAME
        );

        # Restore CGI Session parameters
        for ( $self->{_cgisession}->param ) {
            my $value = $self->{_cgisession}->param($_);
            $session->{prefs}->setInternalPreferences( $_ => $value );
        }

        # May end up doing this several times; but this is the only place
        # if should really need to be done, unless someone allocates a
        # new response object.
        $self->_addSessionCookieToResponse();
    }

  if ( $self->{hasLdap} && $self->{UseLdap} ) {
    my $origUser = $authUser;
    $authUser = Foswiki::Sandbox::untaintUnchecked( $authUser );
    if ( defined $authUser ) {
      $authUser =~ s/^\s+//o;
      $authUser =~ s/\s+$//o;

      $authUser = lc( $authUser ) if ( $self->{ldap}{caseSensitivity} eq 'off' );
      $authUser = $self->{ldap}->normalizeLoginName( $authUser ) if $self->{ldap}{normalizeLoginName};

      unless ( $self->{ldap}{excludeMap}{$authUser} ) {
        $self->{ldap}->checkCacheForLoginName( $authUser );
      } else {
        return $origUser;
      }
    }
  }

  return $authUser;
}

sub loginUrl {
  my $self    = shift;
  my $session = $self->{session};
  my $topic   = $session->{topicName};
  my $web     = $session->{webName};
  return $session->getScriptUrl( 0, 'login', $web, $topic,
    foswiki_origin => _packRequest( $session ) );
}

sub login {
  my ( $self, $query, $session ) = @_;
  my $users = $session->{users};

  my $origin = $query->param( 'foswiki_origin' );
  my ( $origurl, $origmethod, $origaction ) = _unpackRequest( $origin );
  my $loginName = $query->param( 'username' );
  my $loginPass = $query->param( 'password' );
  my $remember  = $query->param( 'remember' );

  # Eat these so there's no risk of accidental passthrough
  $query->delete( 'foswiki_origin', 'username', 'password' );

  # UserMappings can over-ride where the login template is defined
  my $loginTemplate = $users->loginTemplateName();    #defaults to login.tmpl
  my $tmpl = $session->templates->readTemplate( $loginTemplate );

  my $banner = $session->templates->expandTemplate( 'LOG_IN_BANNER' );
  my $note   = '';
  my $topic  = $session->{topicName};
  my $web    = $session->{webName};

  my $cgisession = $self->{_cgisession};

  $cgisession->param( 'REMEMBER', $remember ) if $cgisession;
  if ( $cgisession && $cgisession->param( 'AUTHUSER' )
    && $loginName && $loginName ne $cgisession->param( 'AUTHUSER' ) )
  {
      $banner = $session->templates->expandTemplate( 'LOGGED_IN_BANNER' );
      $note   = $session->templates->expandTemplate( 'NEW_USER_NOTE' );
  }

  my $error = '';

  if ( $loginName ) {
    my $defaultRealm = $Foswiki::cfg{Plugins}{KerberosPlugin}{DefaultRealm};
    my $realms = $Foswiki::cfg{Plugins}{KerberosPlugin}{Realms};
    my $kerberos = new Authen::Krb5::Simple();

    unless ( $defaultRealm && $realms ) {
      $session->{response}->status( 200 );
      $session->logger->log(
        {
          level    => 'info',
          action   => 'login',
          webTopic => $web . '.' . $topic,
          extra    => "AUTHENTICATION FAILURE - Realm(s) not specified or unreachable.",
        }
      );

      $banner = $session->templates->expandTemplate( 'MISSING_REALM' );
    }

    my $adminLogin = $loginName eq $Foswiki::cfg{AdminUserLogin} &&
        $Foswiki::cfg{Plugins}{KerberosPlugin}{DontUseKerberosForAdminUser};

    if ( $defaultRealm || $realms || $adminLogin ) {
      my $validation;
      if ( $adminLogin ) {
        $validation = $users->checkPassword( $loginName, $loginPass );
        $error = $users->passwordError($loginName);
      } else {
        if ( $loginName =~ m/^(.+)\\(.+)$/ ) {
          $kerberos->realm( $realms->{$1} );

          # SMELL: verify loginName -> is it legal to cut off the domain??
          $loginName = $2;
          $validation = $kerberos->authenticate( $loginName, $loginPass ) if $realms;
        } else {
          $kerberos->realm( $realms->{$defaultRealm} ) if $defaultRealm;
          $validation = $kerberos->authenticate( $loginName, $loginPass ) if $defaultRealm;
        }

        $error = $kerberos->errstr();
      }

      if ( $validation ) {
        # SUCCESS our user is authenticated. Note that we may already
        # have been logged in by the userLoggedIn call in loadSession,
        # because the username-password URL params are the same as
        # the params passed to this script, and they will be used
        # in loadSession if no other user info is available.
        $self->userLoggedIn( $loginName );
        $session->logger->log(
          {
            level    => 'info',
            action   => 'login',
            webTopic => $web . '.' . $topic,
            extra    => "AUTHENTICATION SUCCESS - $loginName - "
          }
        );

        # remove the sudo param - its only to tell TemplateLogin
        # that we're using BaseMapper..
        $query->delete( 'sudo' );

        $cgisession->param( 'VALIDATION', $validation ) if $cgisession;

        if ( !$origurl || $origurl eq $query->url() ) {
          $origurl = $session->getScriptUrl( 0, 'view', $web, $topic );
        } else {
          # Unpack params encoded in the origurl and restore them
          # to the query. If they were left in the query string they
          # would be lost if we redirect with passthrough.
          # First extract the params, ignoring any trailing fragment.
          if ( $origurl =~ s/\?([^#]*)// ) {
            foreach my $pair ( split( /[&;]/, $1 ) ) {
              if ( $pair =~ /(.*?)=(.*)/ ) {
                $query->param( $1, TAINT( $2 ) );
              }
            }
          }

          # Restore the action too
          $query->action( $origaction ) if $origaction;
        }

        # Restore the method used on origUrl so if it was a GET, we
        # get another GET.
        $query->method( $origmethod );
        $session->redirect( $origurl, 1 );
        return;
      }
      else {
        # Tasks:Item1029  After much discussion, the 403 code is not
        # used for authentication failures. RFC states: "Authorization
        # will not help and the request SHOULD NOT be repeated" which
        # is not the situation here.
        $session->{response}->status( 200 );
        $session->logger->log(
          {
            level    => 'info',
            action   => 'login',
            webTopic => $web . '.' . $topic,
            extra    => "AUTHENTICATION FAILURE - $loginName - ",
          }
        );

       $banner = $session->templates->expandTemplate( 'UNRECOGNISED_USER' );
      }
    }
  } else {
    # If the loginName is unset, then the request was likely a perfectly
    # valid GET call to http://foswiki/bin/login
    # 4xx cannot be a correct status, as we want the user to retry the
    # same URL with a different login/password
    $session->{response}->status( 200 );
  }

  # Remove the validation_key from the *passed through* params. It isn't
  # required, because the form will have a new validation key, and
  # giving the parameter twice will confuse the strikeone Javascript.
  $session->{request}->delete( 'validation_key' );

  # set the usernamestep value so it can be re-displayed if we are here due
  # to a failed authentication attempt.
  $query->param( -name => 'usernamestep', -value => $loginName );

  # TODO: add JavaScript password encryption in the template
  $origurl ||= '';

  # Set session preferences that will be expanded when the login
  # template is instantiated
  $session->{prefs}->setSessionPreferences(
    FOSWIKI_ORIGIN => Foswiki::entityEncode(
      _packRequest( $origurl, $origmethod, $origaction )
    ),

    # Path to be used in the login form action.
    # Could have used %ENV{PATH_INFO} (after extending {AccessibleENV})
    # but decided against it as the path_info might have been rewritten
    # from the original env var.
    PATH_INFO => $query->path_info(),
    BANNER    => $banner,
    NOTE      => $note,
    ERROR     => $error
  );

  my $topicObject = Foswiki::Meta->new( $session, $web, $topic );
  $tmpl = $topicObject->expandMacros( $tmpl );
  $tmpl = $topicObject->renderTML( $tmpl );
  $tmpl =~ s/<nop>//g;
  $session->writeCompletePage( $tmpl );
}

sub getUser {
  my $self = shift;
  my $query = $self->{session}->{request};

  return unless $query;
  my $remoteUser = $query->remote_user();
  return unless $remoteUser;

  my $tmpUser = $remoteUser;
  $tmpUser =~ s/(.*)\@.*/$1/;
  my @users = split( ',', $Foswiki::cfg{Plugins}{KerberosPlugin}{NonKerberosUsers} );
  foreach my $user (@users) {
    return if ( $user eq $tmpUser );
  }

  my $stripRealm = $Foswiki::cfg{Plugins}{KerberosPlugin}{StripRealmFromLoginName};
  if ( $stripRealm ) {
    $remoteUser =~ s/(.*)\@.*/$1/;
  }

  if ( $self->{hasLdap} && $self->{UseLdap} && $self->{DenyNonLdapUser} ) {
    my $account = $self->{ldap}->getAccount($remoteUser);
    Foswiki::Func::setSessionValue( "KRB_PREV_AUTO_LOGIN_ATTEMPT", 1 );
    return unless defined $account;
  }

  $self->userLoggedIn( $remoteUser );
  return $remoteUser;
}

1;
