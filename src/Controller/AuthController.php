<?php

namespace Drupal\auth0\Controller;

if (file_exists(AUTH0_PATH . '/vendor/autoload.php')) {
  require_once AUTH0_PATH . '/vendor/autoload.php';
}

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;

use Drupal\auth0\Event\Auth0UserSigninEvent;
use Drupal\auth0\Event\Auth0UserSignupEvent;

use Auth0SDK\Auth0;

/**
 * Controller routines for auth0 routes.
 */
class AuthController extends ControllerBase {

  protected $eventDispatcher;

  /**
   * Set service dependencies.
   *
   * @todo inject the event_dispatcher service.
   */
  public function __construct() {
    $this->eventDispatcher = \Drupal::service('event_dispatcher');;
  }

  /**
   * Handles the login page override.
   */
  public function login() {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $lockExtraSettings = $config->get('auth0_lock_extra_settings');

    if (trim($lockExtraSettings) == "") {
      $lockExtraSettings = "{}";
    }

    return array(
      '#theme' => 'auth0_login',
      '#domain' => $config->get('auth0_domain'),
      '#clientID' => $config->get('auth0_client_id'),
      '#state' => NULL,
      '#showSignup' => $config->get('auth0_allow_signup'),
      '#widgetCdn' => $config->get('auth0_widget_cdn'),
      '#loginCSS' => $config->get('auth0_login_css'),
      '#lockExtraSettings' => $lockExtraSettings,
      '#callbackURL' => "$base_root/auth0/callback",
    );

  }

  /**
   * Handles the callback for the oauth transaction.
   */
  public function callback(Request $request) {
    global $base_root;

    $config = \Drupal::service('config.factory')->get('auth0.settings');

    $auth0 = new Auth0(array(
      'domain'        => $config->get('auth0_domain'),
      'client_id'     => $config->get('auth0_client_id'),
      'client_secret' => $config->get('auth0_client_secret'),
      'redirect_uri'  => "$base_root/auth0/callback",
      'store'         => FALSE,
    ));

    $userInfo = NULL;

    try {
      $userInfo = $auth0->getUserInfo();
      $idToken = $auth0->getIdToken();
    }
    catch (\Exception $e) {

    }

    if ($userInfo) {
      return $this->auth0_login_auth0_user($request, $userInfo, $idToken);
    }
    else {
      drupal_set_message(t('There was a problem logging you in, sorry by the inconvenience.'), 'error');

      return new RedirectResponse('/');
    }
  }

  protected function auth0_login_auth0_user(Request $request, $userInfo, $idToken) {
    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $requires_email = $config->get('auth0_requires_verified_email');

    if ($requires_email) {
      if (!isset($userInfo['email']) || empty($userInfo['email'])) {
        drupal_set_message(
          t('This account does not have an email associated. Please login with a different provider.'),
          'error'
        );

        return new RedirectResponse('/');
      }
      if (!$userInfo['email_verified']) {
        return $this->auth0_fail_with_verify_email($idToken);
      }
    }

    // See if there is a user in the auth0_user table with the user info client
    // id.
    $user = $this->auth0_find_auth0_user($userInfo['user_id']);

    if ($user) {
      // User exists!
      // Update the auth0_user with the new userInfo object.
      $this->auth0_update_auth0_object($userInfo);

      user_login_finalize($user);

      $event = new Auth0UserSigninEvent($user, $userInfo);
      $this->eventDispatcher->dispatch(Auth0UserSigninEvent::NAME, $event);

    }
    else {
      // If the user doesn't exist we need to either create a new one, or
      // assign him to an existing one.
      $isDatabaseUser = FALSE;
      foreach ($userInfo['identities'] as $identity) {
        if ($identity['provider'] == "auth0") {
          $isDatabaseUser = TRUE;
        }
      }
      $joinUser = FALSE;
      // If the user has a verified email or is a database user try to see if
      // there is a user to join with. The isDatabase is because we don't want
      // to allow database user creation if there is an existing one with no
      // verified email.
      if ($userInfo['email_verified'] || $isDatabaseUser) {
        $joinUser = user_load_by_mail($userInfo['email']);
      }

      if ($joinUser) {
        // If we are here, we have a potential join user.
        // Don't allow creation or assignation of user if the email is not
        // verified, that would be hijacking.
        if (!$userInfo['email_verified']) {
          return $this->auth0_fail_with_verify_email($idToken);
        }
        $user = $joinUser;
      }
      else {
        // If we are here, we need to create the user.
        $user = $this->auth0_create_user_from_auth0($userInfo);
      }

      $this->auth0_insert_auth0_user($userInfo, $user->id());

      user_login_finalize($user);

      $event = new Auth0UserSignupEvent($user, $userInfo);
      $this->eventDispatcher->dispatch(Auth0UserSignupEvent::NAME, $event);
    }

    if ($request->request->has('destination')) {
      return $this->redirect($request->request->get('destination'));
    }

    return $this->redirect('entity.user.canonical', array('user' => $user->id()));
  }

  protected function auth0_fail_with_verify_email($idToken) {

    $url = Url::fromRoute('auth0.verify_email', array(), array("query" => array('token' => $idToken)));

    drupal_set_message(
      t("Please verify your email and log in again. Click <a href=@url>here</a> to Resend verification email.",
        array(
          '@url' => $url->toString(),
        )
    ), 'warning');

    return new RedirectResponse('/');
  }

  protected function auth0_find_auth0_user($id) {
    $rs = db_select('auth0_user', 'a')
      ->fields('a', array('drupal_id'))
      ->condition('auth0_id', $id, '=')
      ->execute()
      ->fetchAssoc();

    return empty($rs) ? FALSE : User::load($rs['drupal_id']);
  }

  protected function auth0_update_auth0_object($userInfo) {
    db_update('auth0_user')
      ->fields(array(
        'auth0_object' => serialize($userInfo),
      ))
      ->condition('auth0_id', $userInfo['user_id'], '=')
      ->execute();
  }

  protected function auth0_insert_auth0_user($userInfo, $uid) {

    db_insert('auth0_user')->fields(array(
      'auth0_id' => $userInfo['user_id'],
      'drupal_id' => $uid,
      'auth0_object' => json_encode($userInfo),
    ))->execute();

  }

  protected function auth0_create_user_from_auth0($userInfo) {

    // @todo Use this variable or remove it.
    $language = \Drupal::languageManager()->getCurrentLanguage()->getId();
    $user = User::create();

    $user->setPassword(uniqid('auth0', TRUE));
    $user->enforceIsNew();

    if (isset($userInfo['email']) && !empty($userInfo['email'])) {
      $user->setEmail($userInfo['email']);
    }
    else {
      $user->setEmail("change_this_email@" . uniqid() . ".com");
    }

    // If the username already exists, create a new random one.
    $username = $userInfo['nickname'];
    if (user_load_by_name($username)) {
      $username .= time();
    }

    $user->setUsername($username);
    $user->activate();
    $user->save();

    return $user;
  }

  public function verify_email(Request $request) {
    $token = $request->get('token');

    $config = \Drupal::service('config.factory')->get('auth0.settings');
    $secret = $config->get('auth0_client_secret');

    try {
      $user = \JWT::decode($token, base64_decode(strtr($secret, '-_', '+/')));

      $userId = $user->sub;
      $domain = $config->get('auth0_domain');
      $url = "https://$domain/api/users/$userId/send_verification_email";

      $client = \Drupal::httpClient();

      $response = $client->request('POST', $url, array(
        "headers" => array(
          "Authorization" => "Bearer $token",
        ),
      ));

      drupal_set_message(t('An Authorization email was sent to your account'));
    }
    catch (\UnexpectedValueException $e) {
      drupal_set_message(t('Your session has expired.'), 'error');
    }
    catch (\Exception $e) {
      drupal_set_message(t('Sorry, we couldnt send the email'), 'error');
    }

    return new RedirectResponse('/');
  }

}
