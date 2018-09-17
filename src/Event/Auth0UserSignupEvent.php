<?php

namespace Drupal\auth0\Event;

use Symfony\Component\EventDispatcher\Event;
use Drupal\user\UserInterface;

/**
 * User signup event.
 */
class Auth0UserSignupEvent extends Event {

  /**
   * The event name.
   */
  const NAME = 'auth0.signup';

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
   * Initialize the event.
   *
   * @param \Drupal\user\UserInterface $user
   *   The current user.
   * @param array $auth0Profile
   *   The Auth0 profile array.
   */
  public function __construct(UserInterface $user, array $auth0Profile) {
    $this->user = $user;
    $this->auth0Profile = $auth0Profile;
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
   *   The Auth0 profile.
   */
  public function getAuth0Profile() {
    return $this->auth0Profile;
  }

}
