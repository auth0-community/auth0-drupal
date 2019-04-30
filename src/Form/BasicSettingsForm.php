<?php

namespace Drupal\auth0\Form;

/**
 * @file
 * Contains \Drupal\auth0\Form\BasicSettingsForm.
 */

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\auth0\Util\AuthHelper;

/**
 * This forms handles the basic module configurations.
 */
class BasicSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'auth0_basic_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'auth0.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {

    $config = $this->configFactory()->get('auth0.settings');

    $form['auth0_domain'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Domain'),
      '#default_value' => $config->get('auth0_domain'),
      '#description' => $this->t('The Auth0 Domain for this Application, found in the Auth0 Dashboard.'),
      '#required' => TRUE,
    ];

    $form['auth0_custom_domain'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Custom Domain'),
      '#default_value' => $config->get('auth0_custom_domain') ?: '',
      '#description' => $this->t('Your Auth0 custom domain, if in use.'),
      '#required' => FALSE,
    ];

    $form['auth0_client_id'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client ID'),
      '#default_value' => $config->get('auth0_client_id'),
      '#description' => $this->t('Client ID from the Application settings page in your Auth0 dashboard.'),
      '#required' => TRUE,
    ];

    $form['auth0_client_secret'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Client Secret'),
      '#default_value' => $config->get('auth0_client_secret'),
      '#description' => $this->t('Client Secret from the Application settings page in your Auth0 dashboard.'),
      '#required' => TRUE,
    ];

    $form['auth0_secret_base64_encoded'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Client Secret is base64 Encoded'),
      '#default_value' => $config->get('auth0_secret_base64_encoded'),
      '#description' => $this->t('This is stated below the Client Secret field on the Application settings page in your Auth0 dashboard.'),
    ];

    $form[AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM] = [
      '#type' => 'select',
      '#title' => $this->t('JsonWebToken Signature Algorithm'),
      '#options' => [
        'HS256' => $this->t('HS256'),
        'RS256' => $this->t('RS256'),
      ],
      '#default_value' => $config->get(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM) ?: AUTH0_DEFAULT_SIGNING_ALGORITHM,
      '#description' => $this->t('Your JWT Signing Algorithm for the ID token. RS256 is recommended and must be set in the advanced settings for this client under the OAuth tab.'),
      '#required' => TRUE,
    ];

    $form['actions']['#type'] = 'actions';

    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => $this->t('Save'),
      '#button_type' => 'primary',
    ];

    return $form;

  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    if (empty($form_state->getValue('auth0_client_id'))) {
      $form_state->setErrorByName('auth0_client_id', $this->t('Please complete the application Client ID'));
    }

    if (empty($form_state->getValue('auth0_client_secret'))) {
      $form_state->setErrorByName('auth0_client_secret', $this->t('Please complete the application Client Secret'));
    }

    if (empty($form_state->getValue('auth0_domain'))) {
      $form_state->setErrorByName('auth0_domain', $this->t('Please complete your Auth0 domain'));
    }

    if (empty($form_state->getValue(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM))) {
      $form_state->setErrorByName(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM, $this->t('Please complete your Auth0 Signature Algorithm'));
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $config = $this->configFactory()->getEditable('auth0.settings');
    $config->set('auth0_client_id', $form_state->getValue('auth0_client_id'))
      ->set('auth0_client_secret', $form_state->getValue('auth0_client_secret'))
      ->set('auth0_domain', $form_state->getValue('auth0_domain'))
      ->set('auth0_custom_domain', $form_state->getValue('auth0_custom_domain'))
      ->set(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM, $form_state->getValue(AuthHelper::AUTH0_JWT_SIGNING_ALGORITHM))
      ->set('auth0_secret_base64_encoded', $form_state->getValue('auth0_secret_base64_encoded'))
      ->save();

    $this->messenger()->addStatus($this->t('Saved!'));
  }

}
