(function($) {

  $(document).ready( function() {
    if ( foswiki.preferences.KERBEROSAUTOLOGIN == 1 ) {
      return;
    }

    var login = $('div#foswikiLogin');
    if ( login == undefined ) return;
    var form = $(login).find('form');
    var steps = $(form).find('div.foswikiFormStep');
    $.each( steps, function( i, v) {
      if ( i != 0 ) {
        $(v).hide();
      }
    });

    var pubUrl = foswiki.getPreference( 'PUBURL' );
    $(form).append( '<div class="foswikiFormStep KerberosPlugin"><img src="' + pubUrl +'/System/KerberosPlugin/assets/processing-bg.gif" />&nbsp;Please wait...</tmp>' );

    var scriptPrefix = foswiki.getPreference( 'SCRIPTURLPATH' );
    $.ajax( {
      type: "GET",
      url: scriptPrefix + "/krblogin",
      success: function( data, msg, xhr ) {
        krbUpdateStatus();
        var scriptUrl = foswiki.getPreference( 'SCRIPTURL' ):
        var scriptSuffix = foswiki.getPreference( 'SCRIPTSUFFIX' );
        var web = foswiki.getPreference('WEB');
        var topic = foswiki.getPreference('TOPIC');
        var url = scriptUrl '/view' + scriptSuffix + '/' + web + '/' + topic;
        window.location.href = url;
      },
      error: function( x, m, e ) {
        krbUpdateStatus();
        $(form).find('div.KerberosPlugin').remove();
        $.each( steps, function( i, v) {
          if ( i != 0 ) {
            $(v).fadeIn( 'slow' );
          }
        } );
      }
    } );
  } );
} )(jQuery);

function krbUpdateStatus() {
  var scriptPrefix = foswiki.getPreference( 'SCRIPTURLPATH' );
  var scriptSuffix = foswiki.getPreference( 'SCRIPTSUFFIX' );
  var usersWeb = foswiki.getPreference( 'USERSWEB' );
  var location = window.location.pathname;
  location = location == "/" ? usersWeb : location;
  $.ajax( {
    type: "GET",
    url: scriptPrefix + "/rest" + scriptSuffix + "/KerberosPlugin/Update",
    data: { "location": location },
    success: function( data, msg, xhr ) {
       $('div#krb-autologin').fadeOut( "slow", function() {
         var div = $(data).hide();
         $(this).replaceWith( data );
         $(data.id).fadeIn( "slow" );
       });
    },
    error: function( xhr, msg, err ) { /* mal scharf überlegen, was man hier anzeigen könnte. an dieser stelle ist ein fehler absolut unkritisch */ }
  } );
}

function krbAutoLogin() {
  var pubUrl = foswiki.getPreference( 'PUBURL' );
  var scriptPrefix = foswiki.getPreference( 'SCRIPTURLPATH' );
  $( '#krb-placeholder' ).replaceWith( '<img src="' + pubUrl +'/System/KerberosPlugin/assets/processing-bg.gif" />' );
  $.ajax( {
    type: "GET",
    url: scriptPrefix + "/krblogin",
    success: function( data, msg, xhr ) {
      krbUpdateStatus();

      var scriptUrl = foswiki.getPreference( 'SCRIPTURL' ):
      var scriptSuffix = foswiki.getPreference( 'SCRIPTSUFFIX' );
      var web = foswiki.getPreference('WEB');
      var topic = foswiki.getPreference('TOPIC');
      var url = scriptUrl '/view' + scriptSuffix + '/' + web + '/' + topic;
      $.ajax( {
        type: "GET",
        url: url,
        success: function( d, m, x ) {
          var newStyle = undefined;
          $(d).filter('style').each( function() {
            var text = $(this).text();
            if ( text.search( 'requireModacChangePermission' ) >= 0 ) {
              newStyle = text;
            }
          } );

          if ( newStyle == undefined ) {
            return;
          }

          $('head').find("style:contains('.requireModacChangePermission')").each( function() {
            $(this).replaceWith( newStyle );
          } );
        }
      } );
    },
    error: function( xhr, msg, err ) {
      krbUpdateStatus();
    }
  } );
}
