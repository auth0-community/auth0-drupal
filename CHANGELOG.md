# Change Log

## [8.x-2.2](https://github.com/auth0/wp-auth0/tree/8.x-2.2) (2019-05-10)
[Full Changelog](https://github.com/auth0/wp-auth0/compare/8.x-2.1...8.x-2.2)

**Closed issues**
- Failed to exchange code for tokens: Invalid state [\#139](https://github.com/auth0/auth0-drupal/issues/139)
- Issue with returnTo/state post callback [\#136](https://github.com/auth0/auth0-drupal/issues/136)
- Invalid token [\#130](https://github.com/auth0/auth0-drupal/issues/130)
- drupal jwt  [\#128](https://github.com/auth0/auth0-drupal/issues/128)
- Resend verification link leads to blank page [\#126](https://github.com/auth0/auth0-drupal/issues/126)
- How to set user roles based on app_metadata? [\#123](https://github.com/auth0/auth0-drupal/issues/123)
- What happens if exception happens in Drupal? [\#118](https://github.com/auth0/auth0-drupal/issues/118)
- Fix settings form pages [\#93](https://github.com/auth0/auth0-drupal/issues/93)

**Added**
- add/port prelogin event [\#132](https://github.com/auth0/auth0-drupal/pull/132) ([edysmp](https://github.com/edysmp))
- Send correct telemetry for Drupal [\#131](https://github.com/auth0/auth0-drupal/pull/131) ([joshcanhelp](https://github.com/joshcanhelp))
- Add custom domain setting and add new callback error checking [\#125](https://github.com/auth0/auth0-drupal/pull/125) ([identitysolutions](https://github.com/identitysolutions))

**Changed**
- Settings page cleanup [\#138](https://github.com/auth0/auth0-drupal/pull/138) ([joshcanhelp](https://github.com/joshcanhelp))

**Fixed**
- Fix redirectTo URL parameter [\#137](https://github.com/auth0/auth0-drupal/pull/137) ([joshcanhelp](https://github.com/joshcanhelp))
- Fix inline JavaScript causing resend link not to work [\#129](https://github.com/auth0/auth0-drupal/pull/129) ([joshcanhelp](https://github.com/joshcanhelp))
- De-Duped EmailNotVerifiedException in AuthController::processUserLogin [\#117](https://github.com/auth0/auth0-drupal/pull/117) ([mptap](https://github.com/mptap))

## [8.x-2.1](https://github.com/auth0/wp-auth0/tree/8.x-2.1) (2018-09-28)
[Full Changelog](https://github.com/auth0/wp-auth0/compare/2.0.3...8.x-2.1)

**Closed issues**
- Drupal.org module [\#86](https://github.com/auth0/auth0-drupal/issues/86)

**Changed**
- Update README, remove README.txt, add GH templates [\#112](https://github.com/auth0/auth0-drupal/pull/112) ([joshcanhelp](https://github.com/joshcanhelp))
- Drupal standards scan and external file for Lock JS [\#109](https://github.com/auth0/auth0-drupal/pull/109) ([rob3000](https://github.com/rob3000))

**Fixed**
- Fix "array to string conversion" PHP notices [\#115](https://github.com/auth0/auth0-drupal/pull/115) ([hawkeyetwolf](https://github.com/hawkeyetwolf))
- Fix JSON parsing, role mapping, field mapping, and allow signup [\#113](https://github.com/auth0/auth0-drupal/pull/113) ([joshcanhelp](https://github.com/joshcanhelp))
- PHPCS of AuthHelper [\#105](https://github.com/auth0/auth0-drupal/pull/105) ([rob3000](https://github.com/rob3000))
- PHPCS BasicSettingsForm.php && default value config updates [\#104](https://github.com/auth0/auth0-drupal/pull/104) ([rob3000](https://github.com/rob3000))
- PHPCS for Exceptions [\#103](https://github.com/auth0/auth0-drupal/pull/103) ([rob3000](https://github.com/rob3000))
- PHPCS for BasicAdvancedForm.php [\#102](https://github.com/auth0/auth0-drupal/pull/102) ([rob3000](https://github.com/rob3000))
- PHPCS for Auth0UserSignupEvent.php [\#101](https://github.com/auth0/auth0-drupal/pull/101) ([rob3000](https://github.com/rob3000))
- Updated Auth0UserSigninEvent for Drupal Coding Standards [\#100](https://github.com/auth0/auth0-drupal/pull/100) ([rob3000](https://github.com/rob3000))
- Fixed login for new tenants [\#88](https://github.com/auth0/auth0-drupal/pull/88) ([joshcanhelp](https://github.com/joshcanhelp))
- Updating PHP-SDK library to 5.1 [\#87](https://github.com/auth0/auth0-drupal/pull/87) ([joshcanhelp](https://github.com/joshcanhelp))
