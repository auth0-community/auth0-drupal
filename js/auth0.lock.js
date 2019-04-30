(function ($, Drupal) {

  'use strict';

  /**
   * Implements Auth0 Lock
   */
  Drupal.behaviors.auth0Lock = {
    attach: function (context, settings) {
      var auth0 = settings.auth0;

      if (!auth0) {
        return;
      }

      var lock_options = {};
      if (auth0.lockExtraSettings) {
        try {
          lock_options = JSON.parse(auth0.lockExtraSettings);
        } catch (error) {
          console.error(auth0.jsonErrorMsg);
        }
      }
      lock_options.container = lock_options.container || 'auth0-login-form';
      lock_options.allowSignUp = !!( lock_options.allowSignUp || auth0.showSignup );
      lock_options.auth = lock_options.auth || {};
      lock_options.auth.container = lock_options.auth.container || 'auth0-login-form';
      lock_options.auth.redirectUrl = lock_options.auth.redirectUrl || auth0.callbackURL;
      lock_options.auth.responseType = lock_options.auth.responseType || 'code';
      lock_options.auth.params = lock_options.auth.params || {};
      lock_options.auth.params.scope = lock_options.auth.params.scope || auth0.scopes;
      lock_options.auth.params.state = auth0.state;
      lock_options.languageDictionary = lock_options.languageDictionary || {};
      lock_options.languageDictionary.title = lock_options.languageDictionary.title || auth0.formTitle;
      lock_options.configurationBaseUrl = lock_options.configurationBaseUrl || auth0.configurationBaseUrl;

      if (auth0.offlineAccess === 'TRUE') {
        if (lock_options.auth.params.scope.indexOf('offline_access') < 0) {
          lock_options.auth.params.scope += ' offline_access';
        }
      }

      var lock = new Auth0Lock(auth0.clientId, auth0.domain, lock_options);

      lock.show();
    }
  };

})(window.jQuery, Drupal);
