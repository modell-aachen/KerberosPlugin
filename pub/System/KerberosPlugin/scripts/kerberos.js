function krbUpdateStatus() {
  var location = window.location.pathname;
  location = location == "/" ? "/Main/WebHome" : location;
  $.ajax( {
    type: "GET",
    url: "/bin/rest/KerberosPlugin/Update",
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
  $( '#krb-placeholder' ).replaceWith( '<img src="/pub/System/KerberosPlugin/assets/processing-bg.gif" />' );
  $.ajax( {
    type: "GET",
    url: "/bin/krblogin",
    success: function( data, msg, xhr ) { krbUpdateStatus(); },
    error: function( xhr, msg, err ) { krbUpdateStatus(); }
  } );
}
