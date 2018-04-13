<?php

namespace Drupal\Auth0;

use Drupal\user\Entity\User;
use Drupal\Core\Session\SessionManagerInterface;
use Drupal\user\PrivateTempStoreFactory;
use Drupal\Core\Database\Connection;
use Drupal\Core\Config\ConfigFactory;
use Drupal\Core\Logger\LoggerChannelFactory;
use Drupal\Core\Entity\EntityInterface;

/**
 * Helper for Auth0.
 */
class Auth0Helper {

  const NONCE = 'nonce';

  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';

  const DEFAULT_SCOPE = 'openid email profile';
  const DEFAULT_ALGORITHM = 'RS256';
  const DEFAULT_USERNAME_CLAIM = 'nickname';

  /**
   * Defines the default JWT leeway.
   */
  const AUTH0_JWT_LEEWAY_DEFAULT = 180;

  /**
   * The config.
   *
   * @var \Drupal\Core\Config\ConfigFactory
   */
  protected $config;

  /**
   * The session manager.
   *
   * @var \Drupal\Core\Session\SessionManagerInterface
   */
  protected $sessionManager;

  /**
   * User Temp storage.
   *
   * @var \Drupal\user\PrivateTempStore
   */
  protected $tempStore;

  /**
   * Logs errors and messages.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactory
   */
  protected $logger;

  /**
   * The database connection.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected $connection;

  /**
   * Auth0Helper constructor.
   *
   * @param \Drupal\Core\Config\ConfigFactory $config
   *   The config factory.
   * @param \Drupal\Core\Session\SessionManagerInterface $sessionManager
   *   The session manager.
   * @param \Drupal\user\PrivateTempStoreFactory $tempStoreFactory
   *   The user temp storage.
   * @param \Drupal\Core\Logger\LoggerChannelFactory $logger
   *   The logger for messages.
   * @param \Drupal\Core\Database\Connection $connection
   *   The default storage connection.
   */
  public function __construct(
    ConfigFactory $config,
    SessionManagerInterface $sessionManager,
    PrivateTempStoreFactory $tempStoreFactory,
    LoggerChannelFactory $logger,
    Connection $connection
  ) {

    $this->config = $config->get('auth0.settings');
    $this->sessionManager = $sessionManager;
    $this->tempStore = $tempStoreFactory->get('auth0');
    $this->logger = $logger->get('auth0');
    $this->connection = $connection;
  }

  /**
   * Get the auth0 user profile.
   *
   * @param string $id
   *   The auth0 id.
   *
   * @return bool|\Drupal\Core\Entity\EntityInterface
   *   The user profile or FALSE.
   */
  public function findAuth0User($id) {
    $user = FALSE;

    $auth0_user = $this->connection->select('auth0_user', 'a')
      ->fields('a', ['drupal_id'])
      ->condition('auth0_id', $id, '=')
      ->execute()
      ->fetchAssoc();

    if (!empty($auth0_user)) {
      $user = User::load($auth0_user['drupal_id']);
    }

    return $user;
  }

  /**
   * Update the auth0 user profile.
   *
   * @param array $userInfo
   *   The auth0 user array.
   */
  public function updateAuth0User(array $userInfo) {
    $this->connection->update('auth0_user')
      ->fields([
        'auth0_object' => json_encode($userInfo),
      ])
      ->condition('auth0_id', $userInfo['user_id'], '=')
      ->execute();
  }

  /**
   * Insert the auth0 user.
   *
   * @param array $userInfo
   *   The auth0 user array.
   * @param string $uid
   *   The drupal user id.
   *
   * @throws \Exception
   */
  public function insertAuth0User(array $userInfo, $uid) {
    $this->connection->insert('auth0_user')->fields([
      'auth0_id' => $userInfo['user_id'],
      'drupal_id' => $uid,
      'auth0_object' => json_encode($userInfo),
    ])->execute();
  }

  /**
   * Deletes the auth0 user.
   *
   * @param \Drupal\Core\Entity\EntityInterface $account
   *   The drupal user account.
   */
  public function auth0UserDelete(EntityInterface $account) {
    $this->connection->delete('auth0_user')
      ->condition('drupal_id', $account->uid->value)
      ->execute();
  }

  /**
   * Create the Drupal user based on the Auth0 user profile.
   *
   * @param array $userInfo
   *   User info from auth0.
   *
   * @return \Drupal\User\UserInterface
   *   The drupal user account.
   *
   * @throws \Exception
   */
  public function createDrupalUser(array $userInfo) {

    $user = User::create();

    $user->setPassword($this->generatePassword(16));
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

  /**
   * User to generate user password.
   *
   * @param int $nbBytes
   *   The number of bytes to generate.
   *
   * @return mixed
   *   A string of pseudo-random bytes.
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
   * Generates user password for user account.
   *
   * @param int $length
   *   The length of the password.
   *
   * @return mixed
   *   The generated password.
   *
   * @throws \Exception
   */
  private function generatePassword($length) {
    return substr(preg_replace("/[^a-zA-Z0-9]\+\//", "", base64_encode($this->getRandomBytes($length + 1))), 0, $length);
  }

  /**
   * Create a new nonce in session and return it.
   *
   * @return mixed
   *   The nonce to authenticate.
   *
   * @throws \Drupal\user\TempStoreException
   */
  public function getNonce() {
    // Have to start the session after putting something into the session,
    // or we don't actually start it!
    if (!$this->sessionManager->isStarted() && !isset($_SESSION['auth0_is_session_started'])) {
      $_SESSION['auth0_is_session_started'] = 'yes';
      $this->sessionManager->start();
    }

    $factory = new Factory();
    $generator = $factory->getMediumStrengthGenerator();
    $nonces = $this->tempStore->get(Auth0Helper::NONCE);

    if (!is_array($nonces)) {
      $nonces = [];
    }

    $nonce = base64_encode($generator->generate(32));
    $newNonceArray = array_merge($nonces, [$nonce]);
    $this->tempStore->set(Auth0Helper::NONCE, $newNonceArray);

    return $nonce;
  }

  /**
   * Do our one-time check against the nonce stored in session.
   *
   * @param string $nonce
   *   The key to check.
   *
   * @return bool
   *   If the nonce was correct.
   *
   * @throws \Drupal\user\TempStoreException
   */
  public function compareNonce($nonce) {
    $nonces = $this->tempStore->get(Auth0Helper::NONCE);
    if (!is_array($nonces)) {
      $this->logger->error("Couldn't verify state because there was no nonce in storage");
      return FALSE;
    }

    $index = array_search($nonce, $nonces);

    if ($index !== FALSE) {
      unset($nonces[$index]);
      $this->tempStore->set(Auth0Helper::NONCE, $nonces);
      return TRUE;
    }

    $this->logger->error("%nonce not found in: ", [
      '%nonce' => implode(',', $nonces),
    ]);
    return FALSE;
  }

}
