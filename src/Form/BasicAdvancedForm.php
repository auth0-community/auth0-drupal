<?php

namespace Drupal\auth0\Form;

/**
 * @file
 * Contains \Drupal\auth0\Form\BasicAdvancedForm.
 */

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * This forms handles the advanced module configurations.
 */
class BasicAdvancedForm extends ConfigFormBase {

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

    $form['auth0_form_title'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Form title'),
      '#default_value' => $config->get('auth0_form_title') ?: $this->t('Sign In'),
      '#description' => $this->t('This is the title for the login widget.'),
    ];

    $form['auth0_allow_signup'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Allow user signup'),
      '#default_value' => $config->get('auth0_allow_signup'),
      '#description' => $this->t('If you have database connection you can allow users to signup in the widget.'),
    ];

    $form['auth0_allow_offline_access'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Send a Refresh Token in the Signin Event for offline access'),
      '#default_value' => $config->get('auth0_allow_offline_access'),
      '#description' => $this->t('If you need a refresh token for refreshing an expired session, set this to true, and then a refresh token will be sent in the Signin Event.'),
    ];

    $form['auth0_redirect_for_sso'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Universal Login Page'),
      '#default_value' => $config->get('auth0_redirect_for_sso'),
      '#description' => $this->t('If you are supporting SSO for your customers for other apps, including this application, click this to redirect to your Auth0 Universal Login Page for authentication.'),
    ];

    $form['auth0_widget_cdn'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Lock JS CDN URL'),
      '#default_value' => $config->get('auth0_widget_cdn'),
      '#description' => $this->t('Point this to the latest Lock JS version available in the CDN.') . ' ' .
      sprintf(
                          '<a href="https://github.com/auth0/lock/releases" target="_blank">%s</a>',
                          $this->t('Available Lock JS versions.')
      ),
    ];

    $form['auth0_requires_verified_email'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Requires verified email'),
      '#default_value' => $config->get('auth0_requires_verified_email'),
      '#description' => $this->t('Mark this if you require the user to have a verified email to login.'),
    ];

    $form['auth0_join_user_by_mail_enabled'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Link Auth0 logins to Drupal users by email address'),
      '#default_value' => $config->get('auth0_join_user_by_mail_enabled'),
      '#description' => $this->t('If enabled, when a user logs into Drupal for the first time, the system will use the email
address of the Auth0 user to search for a Drupal user with the same email address and setup a link to that
Drupal user account.
<br/>If not enabled, then a new Drupal user will be created even if a Drupal user with the same email address already exists.
'),
    ];

    $form['auth0_username_claim'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Map Auth0 claim to Drupal user name.'),
      '#default_value' => $config->get('auth0_username_claim') ?: AUTH0_DEFAULT_USERNAME_CLAIM,
      '#description' => $this->t('Maps the given claim field as the Drupal user name field. The default is the nickname claim'),
      '#required' => TRUE,
    ];

    $form['auth0_login_css'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Login widget css'),
      '#default_value' => $config->get('auth0_login_css'),
      '#description' => $this->t('CSS to control the Auth0 login form appearance.'),
    ];

    $form['auth0_lock_extra_settings'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Lock extra settings'),
      '#default_value' => $config->get('auth0_lock_extra_settings'),
      '#description' => $this->t(
        'Valid JSON to pass to the Lock options parameter. Options passed here will override Drupal admin settings <a href="@link" target="_blank">More information and examples.</a>',
        ['@link' => 'https://auth0.com/docs/libraries/lock/v11/configuration']
      ),
    ];

    $form['auth0_auto_register'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Auto Register Auth0 users (ignore site registration settings)'),
      '#default_value' => $config->get('auth0_auto_register'),
      '#description' => $this->t('Enable this option if you want new Auth0 users to automatically be activated within Drupal regardless of the global site visitor registration settings (e.g. requiring admin approval).'),
    ];

    // Enhancement to support mapping claims to user attributes and to roles.
    $form['auth0_claim_mapping'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Mapping of Claims to Profile Fields (one per line):'),
      '#cols' => 50,
      '#rows' => 5,
      '#default_value' => $config->get('auth0_claim_mapping'),
      '#description' => $this->t('Enter claim mappings here in the format &lt;claim_name>|&lt;profile_field_name> (one per line), e.g:
<br/>given_name|field_first_name
<br/>family_name|field_last_name
<br/>
<br/>NOTE: the following Drupal fields are handled automatically and will be ignored if specified above:
<br/>    uid, name, mail, init, is_new, status, pass
<br/>&nbsp;
'),
    ];

    $form['auth0_claim_to_use_for_role'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Claim for Role Mapping:'),
      '#default_value' => $config->get('auth0_claim_to_use_for_role'),
      '#description' => $this->t('Name of the claim to use to map to Drupal roles, e.g. roles.  If the claim contains a list of values, all values will be used in the mappings below.'),
    ];

    $form['auth0_role_mapping'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Mapping of Claim Role Values to Drupal Roles (one per line)'),
      '#default_value' => $config->get('auth0_role_mapping'),
      '#description' => $this->t('Enter role mappings here in the format &lt;Auth0 claim value>|&lt;Drupal role name> (one per line), e.g.:
<br/>admin|administrator
<br/>poweruser|power users
<br/>
<br/>NOTE: for any Drupal role in the mapping, if a user is not mapped to the role, the role will be removed from their profile.
Drupal roles not listed above will not be changed by this module.
<br/>&nbsp;
'),
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

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $config = $this->configFactory()->getEditable('auth0.settings');
    $config->set('auth0_form_title', $form_state->getValue('auth0_form_title'))
      ->set('auth0_allow_signup', $form_state->getValue('auth0_allow_signup'))
      ->set('auth0_allow_offline_access', $form_state->getValue('auth0_allow_offline_access'))
      ->set('auth0_redirect_for_sso', $form_state->getValue('auth0_redirect_for_sso'))
      ->set('auth0_widget_cdn', $form_state->getValue('auth0_widget_cdn'))
      ->set('auth0_requires_verified_email', $form_state->getValue('auth0_requires_verified_email'))
      ->set('auth0_join_user_by_mail_enabled', $form_state->getValue('auth0_join_user_by_mail_enabled'))
      ->set('auth0_username_claim', $form_state->getValue('auth0_username_claim'))
      ->set('auth0_login_css', $form_state->getValue('auth0_login_css'))
      ->set('auth0_auto_register', $form_state->getValue('auth0_auto_register'))
      ->set('auth0_lock_extra_settings', $form_state->getValue('auth0_lock_extra_settings'))
      ->set('auth0_claim_mapping', $form_state->getValue('auth0_claim_mapping'))
      ->set('auth0_claim_to_use_for_role', $form_state->getValue('auth0_claim_to_use_for_role'))
      ->set('auth0_role_mapping', $form_state->getValue('auth0_role_mapping'))
      ->set('auth0_username_claim', $form_state->getValue('auth0_username_claim'))
      ->save();

    $this->messenger()->addStatus($this->t('Saved!'));
  }

}
