package Foswiki::Plugins::KerberosPlugin;

use strict;
use Foswiki::Func ();
use Foswiki::Plugins ();

our $VERSION = "1.0.1";
our $RELEASE = "1.0.1";
our $NO_PREFS_IN_TOPIC = 1;
our $SHORTDESCRIPTION = "Enables wiki-based Kerberos authentication.";

sub initPlugin {

  # kerberos js
  Foswiki::Func::addToZone(
    "script",
    "KERBEROSPLUGIN::Scripts",
    "<script type='text/javascript' src='%PUBURLPATH%/%SYSTEMWEB%/KerberosPlugin/scripts/kerberos.js'></script>",
    "JQUERYPLUGIN"
  );

  # kerberos css
  Foswiki::Func::addToZone(
    "head",
    "KERBEROSPLUGIN",
    "<link rel='stylesheet' type='text/css' media='all' href='%PUBURLPATH%/%SYSTEMWEB%/KerberosPlugin/styles/kerberos.css' />"
  );

  Foswiki::Func::registerTagHandler( 'KRBLOGINBAR', \&_handleLoginBar );
  Foswiki::Func::registerTagHandler( 'KRBUSER', \&_handleKrbUser );

  my %restOpts = ( "authenticate", 0, "http_allow", "GET" );
  Foswiki::Func::registerRESTHandler( "Update", \&_restUpdateLoginBar, %restOpts );
  return 1;
}

sub _handleLoginBar {
  my ( $session, $attrs, $topic, $web ) = @_;

#DELETE ME
#Foswiki::Func::setSessionValue( "KRB_PREV_AUTO_LOGIN_ATTEMPT", 0 );

  my $loginBar;
  Foswiki::Func::readTemplate( "krbloginbar" );
  my $prevAutoLogin = Foswiki::Func::getSessionValue( "KRB_PREV_AUTO_LOGIN_ATTEMPT" );
  unless( $prevAutoLogin ) {
    my $success = Foswiki::Func::setSessionValue( "KRB_PREV_AUTO_LOGIN_ATTEMPT", 1 );
    Foswiki::Func::writeWarning( "Error setting 'KRB_PREV_AUTO_LOGIN_ATTEMPT'" ) unless( $success );
    $loginBar = Foswiki::Func::expandTemplate( "krb::autologin" );
    return $loginBar;
  }

  my $isGuest = _isGuestSession( $session );
  unless( $isGuest ) {
    $loginBar = Foswiki::Func::expandTemplate( "krb::logout" );
    return $loginBar;
  }

  $loginBar = Foswiki::Func::expandTemplate( "krb::login" );
  return $loginBar;
}

sub _handleKrbUser {
  my $session = shift;
  if ( _isGuestSession( $session ) ) {
    return $Foswiki::cfg{DefaultUserWikiName};
  }

  my $user = $session->{user};
  my $wikiName =  Foswiki::Func::getWikiName( $user );
  unless( $wikiName ) {
    return $user;
  }

  return $wikiName;
}

sub _restUpdateLoginBar {
  my $session = shift;

  my $isGuest = _isGuestSession( $session );
  Foswiki::Func::readTemplate( "krbloginbar" );
  my $tmpl = ( $isGuest ? "krb::login" : "krb::logout" );

  my $web = $session->{webName};
  my $topic = $session->{topicName};
  my $data =  Foswiki::Func::expandTemplate( $tmpl );
  $data = Foswiki::Func::expandCommonVariables( $data );
  $data = Foswiki::Func::renderText( $data );
  return $data;
}

sub _isGuestSession {
  my $session = shift;
  my $remoteUser = $session->{user};
  my $wikiName =  Foswiki::Func::getWikiName( $remoteUser );
  my $wikiGuest = $Foswiki::cfg{DefaultUserWikiName};
  return ( $wikiGuest eq $wikiName );
}

1;
