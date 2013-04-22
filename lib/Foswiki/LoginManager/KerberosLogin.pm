package Foswiki::LoginManager::KerberosLogin;

use strict;
use warnings;
use Assert;

use Foswiki::LoginManager ();
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
  if ( $self->{UseLdap} ) {
    $self->{ldap} = Foswiki::Contrib::LdapContrib::getLdapContrib( $session );
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
      -status           => 401,
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

sub loadSession {
  my ( $self, $defaultUser, $pwchecker ) = @_;

  my $isLogout = 0;
  my $session = $self->{session};
  if ( $session->{request} && $session->{request}->param( 'logout' ) ) {
    $isLogout = 1;
  }

  my $user = Foswiki::LoginManager::loadSession( @_ );
  if ( $isLogout ) {
    # Uncomment this force kerberos user to stay logged in
    # Foswiki::Func::setSessionValue( "KRB_PREV_AUTO_LOGIN_ATTEMPT", 0 );
  }

  if ( $self->{UseLdap} ) {
    my $origUser = $user;
    $user = Foswiki::Sandbox::untaintUnchecked( $user );
    if ( defined $user ) {
      $user =~ s/^\s+//o;
      $user =~ s/\s+$//o;
      $user = $self->{ldap}->fromUtf8( $user );

      $user = $self->{ldap}->locale_lc( $user ) if ( $self->{ldap}{caseSensitivity} eq 'off' );
      $user = $self->{ldap}->normalizeLoginName( $user ) if $self->{ldap}{normalizeLoginName};

      unless ( $self->{ldap}{excludeMap}{$user} ) {
        $self->{ldap}->checkCacheForLoginName( $user );
      } else {
        return $origUser;
      }
    }
  }

  return $user;
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
    my $realm = $Foswiki::cfg{Plugins}{KerberosPlugin}{Realm};
    my $kerberos = new Authen::Krb5::Simple( realm => $realm );
    unless ( $realm ) {
      $session->{response}->status( 200 );
      $session->logger->log(
        {
          level    => 'info',
          action   => 'login',
          webTopic => $web . '.' . $topic,
          extra    => "AUTHENTICATION FAILURE - Realm not specified or unreachable.",
        }
      );

      $banner = $session->templates->expandTemplate( 'MISSING_REALM' );
    }

    my $adminLogin = $loginName eq $Foswiki::cfg{AdminUserLogin} &&
        $Foswiki::cfg{Plugins}{KerberosPlugin}{DontUseKerberosForAdminUser};
    
    if ( $realm || $adminLogin ) {
      my $validation;
      if ( $adminLogin ) {
        $validation = $users->checkPassword( $loginName, $loginPass );
        $error = $users->passwordError($loginName);
      } else {
        $validation = $kerberos->authenticate( $loginName, $loginPass ) if $realm;
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

  my $stripRealm = $Foswiki::cfg{Plugins}{KerberosPlugin}{StripRealmFromLoginName};
  if ( $stripRealm ) {
    $remoteUser =~ m/(.*)@.*/;
    $remoteUser = $1;
  }
  
  $self->userLoggedIn( $remoteUser );

  return $remoteUser;
}

1;
