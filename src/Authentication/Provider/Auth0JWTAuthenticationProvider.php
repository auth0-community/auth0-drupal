<?php

namespace Drupal\auth0\Authentication\Provider;

use Auth0\SDK\Exception\CoreException;
use Auth0\SDK\JWTVerifier;
use Drupal\auth0\Authentication\DrupalCacheProvider;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;


/**
 * Class Auth0JWTAuthenticationProvider.
 *
 * @package Drupal\auth0\Authentication\Provider
 */
class Auth0JWTAuthenticationProvider implements AuthenticationProviderInterface {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * Constructs a HTTP basic authentication provider object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager) {
    $this->configFactory = $config_factory;
    $this->entityTypeManager = $entity_type_manager;
  }

  /**
   * Checks whether suitable authentication credentials are on the request.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The request object.
   *
   * @return bool
   *   TRUE if authentication credentials suitable for this provider are on the
   *   request, FALSE otherwise.
   */
  public function applies(Request $request) {
    return !empty($request->headers->get('authorization'));
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $authHeader = $request->headers->get('authorization');
    $config = $this->configFactory->get('auth0.settings');
    $token = trim(str_replace('Bearer ', '', $authHeader));

    $secret = $config->get('auth0_client_secret');
    $client_id = $config->get('auth0_client_id');

    $decoded_token = null;
    try {
      $verifier = new JWTVerifier([
        'valid_audiences' => [$client_id],
        'client_secret' => $secret,
      ]);

      $decoded_token = $verifier->verifyAndDecode($token);
    }
    catch (CoreException $e) {
      throw new AccessDeniedHttpException($e->getMessage());
    }

    return $this->entityTypeManager->getStorage('user')->load($decoded_token->scopes->uid);
  }

  /**
   * {@inheritdoc}
   */
  public function cleanup(Request $request) {}

  /**
   * {@inheritdoc}
   */
  public function handleException(GetResponseForExceptionEvent $event) {
    $exception = $event->getException();
    if ($exception instanceof AccessDeniedHttpException) {
      $event->setException(
        new UnauthorizedHttpException('Invalid consumer origin.', $exception)
      );
      return TRUE;
    }
    return FALSE;
  }

}
