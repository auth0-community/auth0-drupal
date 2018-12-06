<?php

namespace Drupal\auth0\Util;

/**
 * @file
 * Contains \Drupal\auth0\Util\AuthHelper.
 */

use Auth0\SDK\JWTVerifier;
use Auth0\SDK\API\Authentication;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;

/**
 * Controller routines for auth0 authentication.
 */
class AuthHelper {
  const AUTH0_LOGGER = 'auth0_helper';
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CUSTOM_DOMAIN = 'auth0_custom_domain';
  const AUTH0_CLIENT_ID = 'auth0_client_id';
  const AUTH0_CLIENT_SECRET = 'auth0_client_secret';
  const AUTH0_REDIRECT_FOR_SSO = 'auth0_redirect_for_sso';
  const AUTH0_JWT_SIGNING_ALGORITHM = 'auth0_jwt_signature_alg';
  const AUTH0_SECRET_ENCODED = 'auth0_secret_base64_encoded';
  const AUTH0_OFFLINE_ACCESS = 'auth0_allow_offline_access';

  private $logger;
  private $config;
  private $domain;
  private $custom_domain;
  private $clientId;
  private $clientSecret;
  private $redirectForSso;
  private $auth0JwtSignatureAlg;
  private $secretBase64Encoded;

  /**
   * Initialize the Helper.
   *
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(
    LoggerChannelFactoryInterface $logger_factory,
    ConfigFactoryInterface $config_factory
  ) {
    $this->logger = $logger_factory->get(AuthHelper::AUTH0_LOGGER);
    $this->config = $config_factory->get('auth0.settings');
    $this->domain = $this->config->get(AuthHelper::AUTH0_DOMAIN);
    $this->custom_domain = $this->config->get(AuthHelper::AUTH0_CUSTOM_DOMAIN);
    $this->clientId = $this->config->get(AuthHelper::AUTH0_CLIENT_ID);
    $this->clientSecret = $this->config->get(AuthHelper::AUTH0_CLIENT_SECRET);
    $this->redirectForSso = $this->config->get(AuthHelper::AUTH0_REDIRECT_FOR_SSO);
    $this->auth0JwtSignatureAlg = $this->config->get(
      AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM,
      AUTH0_DEFAULT_SIGNING_ALGORITHM
    );
    $this->secretBase64Encoded = FALSE || $this->config->get(AuthHelper::AUTH0_SECRET_ENCODED);
  }

  /**
   * Get the user using token.
   *
   * @param string $refreshToken
   *   The refresh token to use to get the user.
   *
   * @return array
   *   A user array of named claims from the ID token.
   *
   * @throws \Drupal\auth0\Exception\RefreshTokenFailedException
   *   The token failure exception.
   */
  public function getUserUsingRefreshToken($refreshToken) {
    global $base_root;

    $auth0Api = new Authentication($this->getDomain(), $this->clientId, $this->clientSecret);

    try {
      $tokens = $auth0Api->oauth_token([
        'grant_type'    => 'refresh_token',
        'client_id'     => $this->clientId,
        'client_secret' => $this->clientSecret,
        'refresh_token' => $refreshToken,
      ]);

      return $this->validateIdToken($tokens->idToken);
    }
    catch (\Exception $e) {
      throw new RefreshTokenFailedException($e);
    }
  }

  /**
   * Validate the ID token.
   *
   * @param string $idToken
   *   The ID token to validate.
   *
   * @return mixed
   *   A user array of named claims from the ID token.
   *
   * @throws CoreException
   * @throws InvalidTokenException
   * @throws \Exception
   */
  public function validateIdToken($idToken) {
    $auth0_domain = 'https://' . $this->getDomain() . '/';
    $auth0_settings = [];
    $auth0_settings['authorized_iss'] = [$auth0_domain];
    $auth0_settings['supported_algs'] = [$this->auth0JwtSignatureAlg];
    $auth0_settings['valid_audiences'] = [$this->clientId];
    $auth0_settings['client_secret'] = $this->clientSecret;
    $auth0_settings['secret_base64_encoded'] = $this->secretBase64Encoded;
    $jwt_verifier = new JWTVerifier($auth0_settings);
    return $jwt_verifier->verifyAndDecode($idToken);
  }

  /**
   * Return the Domain
   *
   * @param none
   *
   * @return mixed
   *   A string with the domain name
   *   A empty string if the config is not set
   *
   */
  public function getDomain() {
      return isset($this->custom_domain) ? $this->custom_domain : $this->domain;
  }
}
