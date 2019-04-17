<?php

namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;

/**
 * User prelogin event.
 */
class Auth0UserPreLoginEvent extends Event {

  /**
   * The event name.
   */
  const NAME = 'auth0.prelogin';

  /**
   * The Auth0 profile.
   *
   * @var array
   */
  protected $auth0Profile;

  /**
   * Initialize the event.
   *
   * @param array $auth0Profile
   *   The Auth0 profile array.
   */
  public function __construct(array $auth0Profile) {
    $this->auth0Profile = $auth0Profile;
  }

  /**
   * Get the Auth0 profile.
   *
   * @return array
   *   The Auth0 profile.
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
