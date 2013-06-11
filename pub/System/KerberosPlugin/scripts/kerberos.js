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
  var scriptPrefix = foswiki.getPreference( 'SCRIPTURLPATH' );
  $( '#krb-placeholder' ).replaceWith( '<img src="/pub/System/KerberosPlugin/assets/processing-bg.gif" />' );
  $.ajax( {
    type: "GET",
    url: scriptPrefix + "/krblogin",
    success: function( data, msg, xhr ) { krbUpdateStatus(); },
    error: function( xhr, msg, err ) { krbUpdateStatus(); }
  } );
}
