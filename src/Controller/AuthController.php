<?php

namespace Drupal\auth0\Controller;

/**
 * @file
 * Contains \Drupal\auth0\Controller\AuthController.
 */

// Create a variable to store the path to this module.
// Load vendor files if they exist.
define('AUTH0_PATH', drupal_get_path('module', 'auth0'));

if (file_exists(AUTH0_PATH . '/vendor/autoload.php')) {
  require_once AUTH0_PATH . '/vendor/autoload.php';
}

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Drupal\user\Entity\User;
use Drupal\user\PrivateTempStoreFactory;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

use Symfony\Component\DependencyInjection\ContainerInterface;

use Drupal\auth0\Event\Auth0UserSigninEvent;
use Drupal\auth0\Event\Auth0UserSignupEvent;
use Drupal\auth0\Event\Auth0UserPreLoginEvent;
use Drupal\auth0\Exception\EmailNotSetException;
use Drupal\auth0\Exception\EmailNotVerifiedException;
use Drupal\Core\PageCache\ResponsePolicyInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\auth0\Util\AuthHelper;

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\Auth0;
use Auth0\SDK\API\Authentication;
use Auth0\SDK\API\Helpers\State\SessionStateHandler;
use Auth0\SDK\Store\SessionStore;
use GuzzleHttp\Client;

/**
 * Controller routines for auth0 authentication.
 */
class AuthController extends ControllerBase {

  use StringTranslationTrait;

  const SESSION = 'auth0';
  const STATE = 'state';
  const AUTH0_LOGGER = 'auth0_controller';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';

  protected $eventDispatcher;
  protected $tempStore;
  protected $sessionManager;

  /**
   * The logger.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * The config.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $config;

  /**
   * The Auth0 Domain.
   *
   * @var string|null
   */
  protected $domain;

  /**
   * The Auth0 Custom Domain.
   *
   * @var string|null
   */
  protected $customDomain;

  /**
   * The Auth0 client id.
   *
   * @var string|null
   */
  protected $clientId;

  /**
   * The Auth0 client secret.
   *
   * @var string|null
   */
  protected $clientSecret;

  /**
   * If we should redirect for SSO.
   *
   * @var int
   */
  protected $redirectForSso;

  /**
   * The type of Jwt algorithm.
   *
   * @var string
   */
  protected $auth0JwtSignatureAlg;

  /**
   * If the secret is encoded.
   *
   * @var bool
   */
  protected $secretBase64Encoded;

  /**
   * If we allow offline access.
   *
   * @var bool|null
   */
  protected $offlineAccess;

  /**
   * The Auth0 helper.
   *
   * @var \Drupal\auth0\Util\AuthHelper
   */
  protected $helper;

  /**
   * The Auth0 SDK.
   *
   * @var bool
   */
  protected $auth0;

  /**
   * Logger to log 'auth0' messages.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $auth0Logger;

  /**
   * The http client.
   *
   * @var \GuzzleHttp\Client
   */
  protected $httpClient;

  /**
   * Initialize the controller.
   *
   * @param \Drupal\user\PrivateTempStoreFactory $temp_store_factory
   *   The temp store factory.
   * @param \Drupal\Core\Session\SessionManagerInterface $session_manager
   *   The current session.
   * @param \Drupal\Core\PageCache\ResponsePolicyInterface $page_cache
   *   Page cache.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Symfony\Component\EventDispatcher\EventDispatcherInterface $event_dispatcher
   *   The event dispatcher.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\auth0\Util\AuthHelper $auth0_helper
   *   The Auth0 helper.
   * @param \GuzzleHttp\Client $http_client
   *   The http client.
   */
  public function __construct(
    PrivateTempStoreFactory $temp_store_factory,
    SessionManagerInterface $session_manager,
    ResponsePolicyInterface $page_cache,
    LoggerChannelFactoryInterface $logger_factory,
    EventDispatcherInterface $event_dispatcher,
    ConfigFactoryInterface $config_factory,
    AuthHelper $auth0_helper,
    Client $http_client
  ) {
    // Ensure the pages this controller servers never gets cached.
    $page_cache->trigger();

    $this->helper = $auth0_helper;

    $this->eventDispatcher = $event_dispatcher;
    $this->tempStore = $temp_store_factory->get(AuthController::SESSION);
    $this->sessionManager = $session_manager;
    $this->logger = $logger_factory->get(AuthController::AUTH0_LOGGER);
    $this->auth0Logger = $logger_factory->get('auth0');
    $this->config = $config_factory->get('auth0.settings');
    $this->domain = $this->config->get(AuthController::AUTH0_DOMAIN);
    $this->customDomain = $this->config->get(AuthHelper::AUTH0_CUSTOM_DOMAIN);
    $this->clientId = $this->config->get(AuthController::AUTH0_CLIENT_ID);
    $this->clientSecret = $this->config->get(AuthController::AUTH0_CLIENT_SECRET);
    $this->redirectForSso = $this->config->get(AuthController::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0JwtSignatureAlg = $this->config->get(AuthController::AUTH0_JWT_SIGNING_ALGORITHM);
    $this->secretBase64Encoded = FALSE || $this->config->get(AuthController::AUTH0_SECRET_ENCODED);
    $this->offlineAccess = FALSE || $this->config->get(AuthController::AUTH0_OFFLINE_ACCESS);
    $this->httpClient = $http_client;
    $this->auth0 = FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
        $container->get('user.private_tempstore'),
        $container->get('session_manager'),
        $container->get('page_cache_kill_switch'),
        $container->get('logger.factory'),
        $container->get('event_dispatcher'),
        $container->get('config.factory'),
        $container->get('auth0.helper'),
        $container->get('http_client')
    );
  }

  /**
   * Handles the login page override.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return array|\Drupal\Core\Routing\TrustedRedirectResponse
   *   The redirect or a renderable array.
   */
  public function login(Request $request) {
    global $base_root;

    $lockExtraSettings = $this->config->get('auth0_lock_extra_settings');

    if (trim($lockExtraSettings) == "") {
      $lockExtraSettings = "{}";
    }

    $returnTo = $request->request->get('returnTo', $request->query->get('returnTo', NULL));

    // If supporting SSO, redirect to the hosted login page for authorization.
    if ($this->redirectForSso) {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl(NULL, $returnTo));
    }

    /* Not doing SSO, so show login page */
    return [
      '#theme' => 'auth0_login',
      '#loginCSS' => $this->config->get('auth0_login_css'),
      '#attached' => [
        'library' => [
          'auth0/auth0.lock',
        ],
        'drupalSettings' => [
          'auth0' => [
            'clientId' => $this->config->get('auth0_client_id'),
            'domain' => $this->helper->getAuthDomain(),
            'lockExtraSettings' => $lockExtraSettings,
            'configurationBaseUrl' => $this->helper->getTenantCdn($this->config->get('auth0_domain')),
            'showSignup' => $this->config->get('auth0_allow_signup'),
            'callbackURL' => "$base_root/auth0/callback",
            'state' => $this->getNonce($returnTo),
            'scopes' => AUTH0_DEFAULT_SCOPES,
            'offlineAccess' => $this->offlineAccess,
            'formTitle' => $this->config->get('auth0_form_title'),
            'jsonErrorMsg' => $this->t('There was an error parsing the "Lock extra settings" field.'),
          ],
        ],
      ],
    ];
  }

  /**
   * Handles the login page override.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse
   *   The response after logout.
   */
  public function logout() {
    $auth0Api = new Authentication($this->helper->getAuthDomain(), $this->clientId);

    user_logout();

    // If we are using SSO, we need to logout completely from Auth0,
    // otherwise they will just logout of their client.
    return new TrustedRedirectResponse($auth0Api->get_logout_link(
      \Drupal::request()->getSchemeAndHttpHost(),
      $this->redirectForSso ? NULL : $this->clientId
    ));
  }

  /**
   * Create a new nonce in session and return it.
   *
   * @param string $returnTo
   *   The return url.
   *
   * @return string
   *   The nonce string.
   */
  protected function getNonce($returnTo) {
    // Have to start the session after putting something into the session, or
    // we don't actually start it!
    if (!$this->sessionManager->isStarted() && !isset($_SESSION['auth0_is_session_started'])) {
      $_SESSION['auth0_is_session_started'] = 'yes';
      $this->sessionManager->start();
    }

    $sessionStateHandler = new SessionStateHandler(new SessionStore());
    $states = $this->tempStore->get(AuthController::STATE);
    if (!is_array($states)) {
      $states = [];
    }
    $nonce = $sessionStateHandler->issue();
    $states[$nonce] = $returnTo === NULL ? '' : $returnTo;
    $this->tempStore->set(AuthController::STATE, $states);

    return $nonce;
  }

  /**
   * Build the Authorize url.
   *
   * @param null|string $prompt
   *   If prompt=none should be passed, false if not.
   * @param string $returnTo
   *   Local path|null if null, use default of /user.
   *
   * @return string
   *   The URL to redirect to for authorization.
   */
  protected function buildAuthorizeUrl($prompt, $returnTo = NULL) {
    global $base_root;

    $auth0Api = new Authentication($this->helper->getAuthDomain(), $this->clientId);

    $response_type = 'code';
    $redirect_uri = "$base_root/auth0/callback";
    $connection = NULL;
    $state = $this->getNonce($returnTo);
    $additional_params = [];
    $additional_params['scope'] = AUTH0_DEFAULT_SCOPES;

    if ($this->offlineAccess) {
      $additional_params['scope'] .= ' offline_access';
    }

    if ($prompt) {
      $additional_params['prompt'] = $prompt;
    }

    return $auth0Api->get_authorize_link($response_type, $redirect_uri, $connection, $state, $additional_params);
  }

  /**
   * Check for errors.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   * @param string $returnTo
   *   The return url.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse|RedirectResponse|null
   *   The redirect response.
   */
  private function checkForError(Request $request, $returnTo) {
    $error_msg = $this->t('There was a problem logging you in');

    // Check for in URL parameters and REQUEST.
    $error_code = $request->query->get('error', $request->request->get('error'));

    // Errors codes that should be redirected back to Auth0 for authentication.
    $redirect_errors = [
      'login_required',
      'interaction_required',
      'consent_required',
    ];
    if ($error_code && in_array($error_code, $redirect_errors)) {
      return new TrustedRedirectResponse($this->buildAuthorizeUrl(FALSE, $returnTo));
    }
    elseif ($error_code) {
      $error_desc = $request->query->get('error_description', $request->request->get('error_description', $error_code));
      return $this->failLogin($error_msg . ':  ' . $error_desc, $error_desc);
    }

    return NULL;
  }

  /**
   * Handles the callback for the oauth transaction.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Drupal\Core\Routing\TrustedRedirectResponse|null|\Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   *
   * @throws \Auth0\SDK\Exception\CoreException
   *   The Auth0 exception.
   */
  public function callback(Request $request) {
    global $base_root;
    $problem_logging_in_msg = $this->t('There was a problem logging you in, sorry for the inconvenience.');

    $response = $this->checkForError($request, NULL);
    if ($response !== NULL) {
      return $response;
    }

    // Set store to null so that the store is set to SessionStore.
    $this->auth0 = new Auth0([
      'domain'        => $this->helper->getAuthDomain(),
      'client_id'     => $this->clientId,
      'client_secret' => $this->clientSecret,
      'redirect_uri'  => "$base_root/auth0/callback",
      'persist_user' => FALSE,
    ]);

    $userInfo = NULL;
    $refreshToken = NULL;

    // Exchange the code for the tokens (happens behind the scenes in the SDK).
    try {
      $userInfo = $this->auth0->getUser();
      $idToken = $this->auth0->getIdToken();
    }
    catch (\Exception $e) {
      return $this->failLogin(
        $problem_logging_in_msg,
        $this->t('Failed to exchange code for tokens: @exception', ['@exception' => $e->getMessage()])
      );
    }

    if ($this->offlineAccess) {
      try {
        $refreshToken = $this->auth0->getRefreshToken();
      }
      catch (\Exception $e) {
        // Do NOT fail here, just log the error.
        $this->auth0Logger->warning($this->t('Failed getting refresh token: @exception', ['@exception' => $e->getMessage()]));
      }
    }

    try {
      $user = $this->helper->validateIdToken($idToken);
    }
    catch (\Exception $e) {
      return $this->failLogin($problem_logging_in_msg, $this->t('Failed to validate JWT: @exception', ['@exception' => $e->getMessage()]));
    }

    // State value is validated in $this->auth0->getUser() above.
    $returnTo = NULL;
    $validatedState = $request->query->get('state');
    $currentSession = $this->tempStore->get(AuthController::STATE);
    if (!empty($currentSession[$validatedState])) {
      $returnTo = $currentSession[$validatedState];
      unset($currentSession[$validatedState]);
    }

    if ($userInfo) {
      if (empty($userInfo['sub']) && !empty($userInfo['user_id'])) {
        $userInfo['sub'] = $userInfo['user_id'];
      }
      elseif (empty($userInfo['user_id']) && !empty($userInfo['sub'])) {
        $userInfo['user_id'] = $userInfo['sub'];
      }

      if ($userInfo['sub'] != $user->sub) {
        return $this->failLogin($problem_logging_in_msg, $this->t('Failed to verify JWT sub'));
      }

      $this->auth0Logger->notice('Good Login');

      return $this->processUserLogin($request, $userInfo, $idToken, $refreshToken, $user->exp, $returnTo);
    }
    else {
      return $this->failLogin($problem_logging_in_msg, 'No userinfo found');
    }
  }

  /**
   * Checks if the email is valid.
   *
   * @param array $userInfo
   *   The user information.
   *
   * @throws \Drupal\auth0\Exception\EmailNotSetException
   *   When an email hasn't been set.
   * @throws \Drupal\auth0\Exception\EmailNotVerifiedException
   *   When an email hasn't been verified.
   */
  protected function validateUserEmail(array $userInfo) {
    $requires_email = $this->config->get('auth0_requires_verified_email');

    if ($requires_email) {
      if (!isset($userInfo['email']) || empty($userInfo['email'])) {
        throw new EmailNotSetException();
      }
      if (!$userInfo['email_verified']) {
        throw new EmailNotVerifiedException();
      }
    }
  }

  /**
   * Process the Auth0 user profile and sign in or sign the user up.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   * @param array $userInfo
   *   The user data info.
   * @param string $idToken
   *   ID token received during code exchange.
   * @param string $refreshToken
   *   The refresh token.
   * @param int $expiresAt
   *   When the token expires.
   * @param string $returnTo
   *   The return url.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect url.
   *
   * @throws \Exception
   *   An exception.
   */
  protected function processUserLogin(Request $request, array $userInfo, $idToken, $refreshToken, $expiresAt, $returnTo) {
    $this->auth0Logger->notice('process user login');

    $event = new Auth0UserPreLoginEvent($userInfo);
    $this->eventDispatcher->dispatch(Auth0UserPreLoginEvent::NAME, $event);

    try {
      $this->validateUserEmail($userInfo);

      // See if there is a user in the auth0_user table with the user
      // info client ID.
      $this->auth0Logger->notice($userInfo['user_id'] . ' looking up Drupal user by Auth0 user_id');
      $user = $this->findAuth0User($userInfo['user_id']);

      if ($user) {
        $this->auth0Logger->notice('uid of existing Drupal user found');

        // User exists, update the auth0_user with the new userInfo object.
        $this->updateAuth0User($userInfo);

        // Update field and role mappings.
        $this->auth0UpdateFieldsAndRoles($userInfo, $user);

        $event = new Auth0UserSigninEvent($user, $userInfo, $refreshToken, $expiresAt);
        $this->eventDispatcher->dispatch(Auth0UserSigninEvent::NAME, $event);
      }
      else {
        $this->auth0Logger->notice('existing Drupal user NOT found');

        $user = $this->signupUser($userInfo);

        $this->insertAuth0User($userInfo, $user->id());

        $event = new Auth0UserSignupEvent($user, $userInfo);
        $this->eventDispatcher->dispatch(Auth0UserSignupEvent::NAME, $event);
      }
    }
    catch (EmailNotSetException $e) {
      return $this->failLogin($this->t('This account does not have an email associated. Please login with a different provider.'), 'No Email Found');
    }
    catch (EmailNotVerifiedException $e) {
      return $this->auth0FailWithVerifyEmail($idToken);
    }

    user_login_finalize($user);

    if ($returnTo) {
      return new RedirectResponse($returnTo);
    }
    elseif ($request->request->has('destination')) {
      return new RedirectResponse($request->request->get('destination'));
    }

    return $this->redirect('entity.user.canonical', ['user' => $user->id()]);
  }

  /**
   * Fails user login.
   *
   * @param string $message
   *   The message to display.
   * @param string $logMessage
   *   The message to log.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response after fail.
   */
  protected function failLogin($message, $logMessage) {
    $this->logger->error($logMessage);
    \Drupal::messenger()->addError($message);
    if ($this->auth0) {
      $this->auth0->logout();
    }
    return new RedirectResponse('/');
  }

  /**
   * Create or link a new user based on the auth0 profile.
   *
   * @param array $userInfo
   *   The user info data array.
   * @param string $idToken
   *   ID token returned during login.
   *
   * @return bool|mixed
   *   The user object.
   *
   * @throws \Drupal\auth0\Exception\EmailNotVerifiedException
   *   The email not verified exception.
   * @throws \Exception
   */
  protected function signupUser(array $userInfo, $idToken = '') {
    // If the user doesn't exist we need to either create a new one,
    // or assign them to an existing one.
    $isDatabaseUser = FALSE;

    $user_sub_arr = explode('|', $userInfo['user_id']);
    $provider = $user_sub_arr[0];

    if ('auth0' === $provider) {
      $isDatabaseUser = TRUE;
    }

    $joinUser = FALSE;

    $user_name_claim = $this->config->get('auth0_username_claim') ?: AUTH0_DEFAULT_USERNAME_CLAIM;

    // Drupal usernames do not allow pipe characters.
    $user_name_used = !empty($userInfo[$user_name_claim])
      ? $userInfo[$user_name_claim]
      : str_replace('|', '_', $userInfo['user_id']);

    if ($this->config->get('auth0_join_user_by_mail_enabled') && !empty($userInfo['email'])) {
      $this->auth0Logger->notice($userInfo['email'] . ' join user by mail is enabled, looking up user by email');
      // If the user has a verified email or is a database user try to see if
      // there is a user to join with. The isDatabase is because we don't want
      // to allow database user creation if there is an existing one with no
      // verified email.
      if ($userInfo['email_verified'] || $isDatabaseUser) {
        $joinUser = user_load_by_mail($userInfo['email']);
      }
    }
    else {
      $this->auth0Logger->notice($user_name_used . ' join user by username');

      if (!empty($userInfo['email_verified']) || $isDatabaseUser) {
        $joinUser = user_load_by_name($user_name_used);
      }
    }

    if ($joinUser) {
      $this->auth0Logger->notice($joinUser->id() . ' Drupal user found by email with uid');

      // If we are here, we have a potential join user.
      // Don't allow creation or assignation of user if the email is not
      // verified, that would be hijacking.
      if (!$userInfo['email_verified']) {
        throw new EmailNotVerifiedException();
      }
      $user = $joinUser;
    }
    else {
      $this->auth0Logger->notice($user_name_used . ' creating new Drupal user from Auth0 user');

      // If we are here, we need to create the user.
      $user = $this->createDrupalUser($userInfo);

      // Update field and role mappings.
      $this->auth0UpdateFieldsAndRoles($userInfo, $user);
    }

    return $user;
  }

  /**
   * Email not verified error message.
   *
   * @param string $idToken
   *   The id token.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   */
  protected function auth0FailWithVerifyEmail($idToken) {

    $url = Url::fromRoute('auth0.verify_email', [], []);
    $formText = "<form style='display:none' name='auth0VerifyEmail' action=@url method='post'><input type='hidden' value=@token name='idToken'/></form>";
    $linkText = "<a href='javascript:;' onClick='document.forms[\"auth0VerifyEmail\"].submit();'>here</a>";

    return $this->failLogin(
      $this->t("@formText Please verify your email and log in again. Click @linkText to Resend verification email.",
        [
          '@formText' => $formText,
          '@url' => $url->toString(),
          '@token' => $idToken,
          '@linkText' => $linkText,
        ]
    ), 'Email not verified');
  }

  /**
   * Get the auth0 user profile.
   */
  protected function findAuth0User($id) {
    $auth0_user = db_select('auth0_user', 'a')
      ->fields('a', ['drupal_id'])
      ->condition('auth0_id', $id, '=')
      ->execute()
      ->fetchAssoc();

    return empty($auth0_user) ? FALSE : User::load($auth0_user['drupal_id']);
  }

  /**
   * Update the auth0 user profile.
   *
   * @param array $userInfo
   *   The user info array.
   */
  protected function updateAuth0User(array $userInfo) {
    db_update('auth0_user')
      ->fields([
        'auth0_object' => serialize($userInfo),
      ])
      ->condition('auth0_id', $userInfo['user_id'], '=')
      ->execute();
  }

  /**
   * Update the Auth fields.
   *
   * @param array $userInfo
   *   The user info array.
   * @param \Drupal\user\Entity\User $user
   *   The Drupal user entity.
   */
  protected function auth0UpdateFieldsAndRoles(array $userInfo, User $user) {

    $edit = [];
    $this->auth0UpdateFields($userInfo, $user, $edit);
    $this->auth0UpdateRoles($userInfo, $user, $edit);

    $user->save();
  }

  /**
   * Update the $user profile attributes based on the auth0 field mappings.
   *
   * @param array $userInfo
   *   The user info array.
   * @param \Drupal\user\Entity\User $user
   *   The Drupal user entity.
   * @param array $edit
   *   The edit array.
   */
  protected function auth0UpdateFields(array $userInfo, User $user, array &$edit) {
    $auth0_claim_mapping = $this->config->get('auth0_claim_mapping');

    if (isset($auth0_claim_mapping) && !empty($auth0_claim_mapping)) {
      // For each claim mapping, lookup the value, otherwise set to blank.
      $mappings = $this->auth0PipeListToArray($auth0_claim_mapping);

      // Remove mappings handled automatically by the module.
      $skip_mappings = [
        'uid',
        'name',
        'mail',
        'init',
        'is_new',
        'status',
        'pass',
      ];

      foreach ($mappings as $mapping) {
        $this->auth0Logger->notice('mapping ' . $mapping);

        $key = $mapping[1];
        if (in_array($key, $skip_mappings)) {
          $this->auth0Logger->notice('skipping mapping handled already by Auth0 module ' . $mapping);
        }
        else {
          $value = isset($userInfo[$mapping[0]]) ? $userInfo[$mapping[0]] : '';
          $current_value = $user->get($key)->value;
          if ($current_value === $value) {
            $this->auth0Logger->notice('value is unchanged ' . $key);
          }
          else {
            $this->auth0Logger->notice('value changed ' . $key . ' from [' . $current_value . '] to [' . $value . ']');
            $edit[$key] = $value;
            $user->set($key, $value);
          }
        }
      }
    }
  }

  /**
   * Updates the $user->roles of a user based on the Auth0 role mappings.
   *
   * @param array $userInfo
   *   The user info array.
   * @param \Drupal\user\Entity\User $user
   *   The drupal user entity.
   * @param array $edit
   *   The edit array.
   */
  protected function auth0UpdateRoles(array $userInfo, User $user, array &$edit) {
    $this->auth0Logger->notice("Mapping Roles");
    $auth0_claim_to_use_for_role = $this->config->get('auth0_claim_to_use_for_role');

    if (isset($auth0_claim_to_use_for_role) && !empty($auth0_claim_to_use_for_role)) {
      $claim_value = isset($userInfo[$auth0_claim_to_use_for_role]) ? $userInfo[$auth0_claim_to_use_for_role] : '';
      $this->auth0Logger->notice('claim_value ' . print_r($claim_value, TRUE));

      $claim_values = [];
      if (is_array($claim_value)) {
        $claim_values = $claim_value;
      }
      else {
        $claim_values[] = $claim_value;
      }

      $auth0_role_mapping = $this->config->get('auth0_role_mapping');
      $mappings = $this->auth0PipeListToArray($auth0_role_mapping);

      $roles_granted = [];
      $roles_managed_by_mapping = [];

      foreach ($mappings as $mapping) {
        $this->auth0Logger->notice('mapping ' . print_r($mapping, TRUE));
        $roles_managed_by_mapping[] = $mapping[1];

        if (in_array($mapping[0], $claim_values)) {
          $roles_granted[] = $mapping[1];
        }
      }

      $roles_granted = array_unique($roles_granted);
      $roles_managed_by_mapping = array_unique($roles_managed_by_mapping);

      $not_granted = array_diff($roles_managed_by_mapping, $roles_granted);

      $user_roles = $user->getRoles();

      $new_user_roles = array_merge(array_diff($user_roles, $not_granted), $roles_granted);

      $tmp = array_merge(array_diff($user_roles, $new_user_roles), array_diff($new_user_roles, $user_roles));
      if (empty($tmp)) {
        $this->auth0Logger->notice('no changes to roles detected');
      }
      else {
        $this->auth0Logger->notice('changes to roles detected');
        $edit['roles'] = $new_user_roles;
        foreach (array_diff($new_user_roles, $user_roles) as $new_role) {
          $user->addRole($new_role);
        }
        foreach (array_diff($user_roles, $new_user_roles) as $remove_role) {
          $user->removeRole($remove_role);
        }
      }
    }
  }

  /**
   * Convert mappings to a pipelist.
   *
   * @param array $mappings
   *   The mappings array.
   *
   * @return string
   *   The result of the conversion.
   */
  protected function auth0MappingsToPipeList(array $mappings) {
    $result_text = "";
    foreach ($mappings as $map) {
      $result_text .= $map['from'] . '|' . $map['user_entered'] . "\n";
    }
    return $result_text;
  }

  /**
   * Convert pipe list to array.
   *
   * @param string $mappingListTxt
   *   The pipe list string.
   *
   * @return array
   *   An array of items.
   */
  protected function auth0PipeListToArray($mappingListTxt) {
    $return = [];
    $mappings = explode(PHP_EOL, $mappingListTxt);
    foreach ($mappings as $line) {
      if (empty($line) || FALSE === strpos($line, '|')) {
        continue;
      }
      $line_parts = explode('|', $line);
      $return[] = [trim($line_parts[0]), trim($line_parts[1])];
    }
    return $return;
  }

  /**
   * Insert the Auth0 user.
   *
   * @param array $userInfo
   *   The user info array.
   * @param int $uid
   *   The Drupal user id.
   *
   * @throws \Exception
   */
  protected function insertAuth0User(array $userInfo, $uid) {

    db_insert('auth0_user')->fields([
      'auth0_id' => $userInfo['user_id'],
      'drupal_id' => $uid,
      'auth0_object' => json_encode($userInfo),
    ])->execute();

  }

  /**
   * Get random bytes string.
   *
   * @param int $nbBytes
   *   The number of bytes to generate.
   *
   * @return string
   *   The generated string.
   *
   * @throws \Exception
   */
  private function getRandomBytes($nbBytes = 32) {
    $bytes = openssl_random_pseudo_bytes($nbBytes, $strong);
    if (FALSE !== $bytes && TRUE === $strong) {
      return $bytes;
    }
    else {
      throw new \Exception("Unable to generate secure token from OpenSSL.");
    }
  }

  /**
   * Generate a random password.
   *
   * @param int $length
   *   The length of the password.
   *
   * @return bool|string
   *   The generate password.
   *
   * @throws \Exception
   */
  private function generatePassword($length) {
    return substr(preg_replace("/[^a-zA-Z0-9]\+\//", "", base64_encode($this->getRandomBytes($length + 1))), 0, $length);
  }

  /**
   * Create the Drupal user based on the Auth0 user profile.
   *
   * @param array $userInfo
   *   The user info array.
   *
   * @return \Drupal\user\Entity\User
   *   The Drupal user entity.
   *
   * @throws \Exception
   */
  protected function createDrupalUser(array $userInfo) {
    $user_name_claim = $this->config->get('auth0_username_claim');
    if ($user_name_claim == '') {
      $user_name_claim = 'nickname';
    }

    $user = User::create();

    $user->setPassword($this->generatePassword(16));
    $user->enforceIsNew();

    if (!empty($userInfo['email'])) {
      $user->setEmail($userInfo['email']);
    }
    else {
      $user->setEmail("change_this_email@" . uniqid() . ".com");
    }

    // If the username already exists, create a new random one.
    $username = !empty($userInfo[$user_name_claim])
      ? $userInfo[$user_name_claim]
      : $userInfo['user_id'];

    if (user_load_by_name($username)) {
      $username .= time();
    }

    $user->setUsername($username);
    $user->activate();
    $user->save();

    return $user;
  }

  /**
   * Send the verification email.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\RedirectResponse
   *   The redirect response.
   *
   * @throws \Auth0\SDK\Exception\CoreException
   *   Exception thrown when validating email.
   */
  // phpcs:ignore
  public function verify_email(Request $request) {
    $idToken = $request->get('idToken');

    // Validate the ID Token.
    $auth0_domain = 'https://' . $this->domain . '/';
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->auth0JwtSignatureAlg];
    $auth0_settings['valid_audiences'] = [$this->clientId];
    $auth0_settings['client_secret'] = $this->clientSecret;
    $auth0_settings['secret_base64_encoded'] = $this->secretBase64Encoded;
    $jwt_verifier = new JWTVerifier($auth0_settings);

    try {
      $user = $jwt_verifier->verifyAndDecode($idToken);
    }
    catch (\Exception $e) {
      return $this->failLogin($this->t('There was a problem resending the verification email, sorry for the inconvenience.'),
        "Failed to verify and decode the JWT ($idToken) for the verify email page: " . $e->getMessage());
    }

    try {
      $userId = $user->sub;
      $url = "https://$this->domain/api/users/$userId/send_verification_email";

      $client = $this->httpClient;

      $client->request('POST', $url, [
        "headers" => [
          "Authorization" => "Bearer $idToken",
        ],
      ]);
      \Drupal::messenger()->addStatus($this->t('An Authorization email was sent to your account.'));
    }
    catch (\UnexpectedValueException $e) {
      \Drupal::messenger()->addError($this->t('Your session has expired.'));
    }
    catch (\Exception $e) {
      \Drupal::messenger()->addError($this->t('Sorry, we could not send the email.'));
    }

    return new RedirectResponse('/');
  }

}
