<?php

namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;
use Drupal\user\UserInterface;

/**
 * User signin event.
 */
class Auth0UserSigninEvent extends Event {

  /**
  * The event name.
  */
  const NAME = 'auth0.signin';

  /**
   * The current user.
   *
   * @var \Drupal\user\UserInterface
   */
  protected $user;

  /**
   * The Auth0 profile.
   *
   * @var array
   */
  protected $auth0Profile;

  /**
   * The refresh token.
   *
   * @var string
   */
  protected $refreshToken;

  /**
   * The timestamp when the token expires.
   *
   * @var timestamp
   */
  protected $expiresAt;

  /**
   * Initialize the event.
   *
   * @param \Drupal\user\UserInterface $user
   *   The current user.
   * @param array $auth0Profile
   *   The Auth0 profile array.
   * @param string $refreshToken
   *   The refresh token.
   * @param string $expiresAt
   *   The time when the ID Token expires in unix timestamp (seconds only).
   */
  public function __construct(UserInterface $user, array $auth0Profile, $refreshToken, $expiresAt) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
    $this->refreshToken = $refreshToken;
    $this->expiresAt = $expiresAt;
  }

  /**
   * Get the Drupal user.
   *
   * @return \Drupal\user\UserInterface
   *   The current user.
   */
  public function getUser() {
    return $this->user;
  }

  /**
   * Get the Auth0 profile.
   *
   * @return array
   *   The Auth0 profile array.
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

  /**
   * Get the refresh token.
   *
   * @return string
   *   The refresh token.
   */
  public function getRefreshToken() {
    return $this->refreshToken;
  }

  /**
   * Get the time when the ID token expires.
   *
   * @return timestamp
   *   The unix time when token expires.
   */
  public function getExpiresAt() {
    return $this->expiresAt;
  }

}
