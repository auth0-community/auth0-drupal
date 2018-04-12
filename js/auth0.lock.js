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

            var lockOptions = auth0.lockOptions || {};

            lockOptions.container = lockOptions.container || 'auth0-login-form';
            lockOptions.allowSignUp = lockOptions.allowSignUp || auth0.showSignup ? 'true' : 'false';
            lockOptions.auth = lockOptions.auth || {};
            lockOptions.auth.container = lockOptions.auth.container || 'auth0-login-form';
            lockOptions.auth.redirectUrl = lockOptions.auth.redirectUrl || auth0.callbackURL;
            lockOptions.auth.responseType = lockOptions.auth.responseType || 'code';
            lockOptions.auth.params = lockOptions.auth.params || {};
            lockOptions.auth.params.scope = lockOptions.auth.params.scope || auth0.scope;
            lockOptions.auth.params.state = lockOptions.auth.params.state || auth0.state;

            var lock = new Auth0Lock(auth0.clientId, auth0.domain, lockOptions);

            lock.show();
        }
    };

})(window.jQuery, Drupal);