SUMMARY
-------

Single Sign On for Enterprises + Social Login + User/Passwords. For all your
Drupal instances.
Powered by Auth0.

INSTALLATION
------------
Before you start, **make sure the admin user has a valid email that you own**,
read the Technical Notes for more information.

1. On the modules configuration page, select `install new module` and upload the
latest release of this plugin
   as a `.tar.gz` file

2. Enable it on the module page

3. Configure it using your auth0 account.

INSTALLATION FROM GITHUB
------------------------
1. Clone the repo to your modules directory:
$ git clone https://github.com/auth0/auth0-drupal.git $DRUPAL_ROOT/sites/all/modules/auth0-drupal

2. Install composer dependencies:
    $ cd auth0-drupal
    $ curl -sS https://getcomposer.org/installer | php
    $ php composer.phar install

3. Enable it on the module page

4. Configure it using your auth0 account.



AUTH0 CONFIGURATION
-------------------
1. Go to your auth0 dashboard https://manage.auth0.com/
2. Create a new Client with the type "Regular Web Application"
3. In the "Allowed Callback URLs" field, add a URL like
'http://yourdomain.com/auth0/callback'
4. Make a note of your domain, Client ID and Client Secret (also note whether
the Client Secret is base64 encoded or not).
5. If using SSO, make sure to add your site's homepage to the "Allowed Logout
URLs" field in your Tenant > Advanced settings.

MODULE CONFIGURATION
--------------------
You can go to the module configuration by this url
http://<yoursite>/admin/config/people/auth0 or using the menu under the people
configuration tab. You need to at least configure the domain, client id and
client secret on the basic tab, using the information of the auth0 dashboard.

The advance tab contains:
* Form title:
The title to be printed on top of the login widget

* Allow user signup:
This only matters if you have database users enabled, and you want that users
can sign up using the
login widget

* Redirect login for SSO:
This will redirect to your Auth0 Hosted Login Page for login, this will enable
you to use SSO for this site and others in Auth0.  It will also redirect for
logout, so you must add your base URL to the Allowed Logout URLs in your Account
Settings for Auth0 (not your client settings).

* Widget CDN:
Changing this url you can use the latest version of the widget without updating
this plugin

* Requires verified email:
Some of the authentication providers have email, other doesnt (example twitter).
When they do, that email can be verified or not. Meaning, we know that the user
really owns that email account. If you check this box, users will be required to
have a verified email in order to login.

* Login widget css:
This is the basic css used to fit the login widget to the drupal default theme,
but if you have a custom theme, you may want to change this as well

TECHNICAL NOTES
---------------

**IMPORTANT**: By using this plugin you are delegating the site authentication
to Auth0. That means that you won't be using the drupal database to authenticate
users anymore and the default login box won't show anymore. However, we can
still associate your existing users by merging them by email. This section
explains how.

When you install this plugin you have at least one existing user in the
database (the admin user). If the site is already being used, you probably have
more than just the admin. We want you to keep those users, of course.

Auth0 allows multiple authentication providers. You can have social providers
like Facebook, Twitter, Google+, etc., you can have a database of
users/passwords (just like drupal but hosted in Auth0) or you can use an
Enterprise directory like Active Directory, LDAP, Office365, SAML and others.
All those authentication providers might give you an email and a flag indicating
whether the email was verified or not. We use that email (only if its verified)
to associate a previous **existing** user with the one coming from Auth0.

If the email was not verified and there is an account with that email in drupal,
the user will be presented with a message saying that the email was not verified
and a link to "Re-send the verification email".



