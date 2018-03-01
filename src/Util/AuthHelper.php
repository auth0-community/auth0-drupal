<?php
/**
 * @file
 * Contains \Drupal\auth0\Util\AuthHelper.
 */

namespace Drupal\auth0\Util;

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\API\Authentication;
use Auth0\SDK\Exception\CoreException;
use Auth0\SDK\Exception\InvalidTokenException;

/**
 * Controller routines for auth0 authentication.
 */
class AuthHelper {
  const AUTH0_LOGGER = 'auth0_helper';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';
  
  private $logger;
  private $config;
  private $domain;
  private $client_id;
  private $client_secret;
  private $redirect_for_sso;
  private $auth0_jwt_signature_alg;
  private $secret_base64_encoded;

  /**
   * Initialize the Helper.
   */
  public function __construct() {
    $this->logger = \Drupal::logger(AuthHelper::AUTH0_LOGGER);
    $this->config = \Drupal::service('config.factory')->get('auth0.settings');
    $this->domain = $this->config->get(AuthHelper::AUTH0_DOMAIN);
    $this->client_id = $this->config->get(AuthHelper::AUTH0_CLIENT_ID);
    $this->client_secret = $this->config->get(AuthHelper::AUTH0_CLIENT_SECRET);
    $this->redirect_for_sso = $this->config->get(AuthHelper::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0_jwt_signature_alg = $this->config->get(
      AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM,
      AUTH0_DEFAULT_SIGNING_ALGORITHM
    );
    $this->secret_base64_encoded = FALSE || $this->config->get(AuthHelper::AUTH0_SECRET_ENCODED);
  }

  /**
   * @param $refreshToken the refresh token to use to get the user
   * @return user an array of named claims from the ID token
   * @throws \Drupal::auth0::Exception::RefreshTokenFailedException
   */
  public function getUserUsingRefreshToken($refreshToken) {
    global $base_root;

    $auth0Api = new Authentication($this->domain, $this->client_id, $this->client_secret);
    
    try {
        $tokens = $auth0Api->oauth_token([
            'grant_type'    => 'refresh_token',
            'client_id'     => $this->client_id,
            'client_secret' => $this->client_secret,
            'refresh_token' => $refreshToken
        ]);
    
        return $this->validateIdToken($tokens->id_token);    
    } catch(\Exception $e) {
        throw new RefreshTokenFailedException($e);
    }
  }

  /**
   * Validate the ID token
   *
   * @param string $idToken - the ID token to validate
   *
   * @return object
   *
   * @throws CoreException
   * @throws InvalidTokenException
   */
  public function validateIdToken($idToken) {
    $auth0_domain = 'https://' . $this->domain . '/';
    $auth0_settings = array();
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->auth0_jwt_signature_alg];
    $auth0_settings['valid_audiences'] = [$this->client_id];
    $auth0_settings['client_secret'] = $this->client_secret;
    $auth0_settings['secret_base64_encoded'] = $this->secret_base64_encoded;
    $jwt_verifier = new JWTVerifier($auth0_settings);
    return $jwt_verifier->verifyAndDecode($idToken);
  }
}
