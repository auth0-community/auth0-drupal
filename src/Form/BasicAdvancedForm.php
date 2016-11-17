<?php
namespace Drupal\auth0\Form;

/**
 * @file
 * Contains \Drupal\auth0\Form\BasicAdvancedForm.
 */

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * This forms handles the advanced module configurations.
 */
class BasicAdvancedForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'auth0_basic_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {

    $config = $this->configFactory->get('auth0.settings');

    $form['auth0_form_title'] = array(
        '#type' => 'textfield',
        '#title' => t('Form title'),
        '#default_value' => $config->get('auth0_form_title', 'Sign In'),
        '#description' => t('This is the title for the login widget.')
    );

    $form['auth0_allow_signup'] = array(
        '#type' => 'checkbox',
        '#title' => t('Allow user signup'),
        '#default_value' => $config->get('auth0_allow_signup'),
        '#description' => t('If you have database connection you can allow users to signup in the widget.')
    );

    $form['auth0_widget_cdn'] = array(
        '#type' => 'textfield',
        '#title' => t('Widget CDN'),
        '#default_value' => $config->get('auth0_widget_cdn'),
        '#description' => t('Point this to the latest widget available in the CDN.')
    );

    $form['auth0_requires_verified_email'] = array(
        '#type' => 'checkbox',
        '#title' => t('Requires verified email'),
        '#default_value' => $config->get('auth0_requires_verified_email'),
        '#description' => t('Mark this if you require the user to have a verified email to login.')
    );

    $form['auth0_login_css'] = array(
        '#type' => 'textarea',
        '#title' => t('Login widget css'),
        '#default_value' => $config->get('auth0_login_css'),
        '#description' => t('This css controls how the widget look and feel.')
    );

    $form['auth0_lock_extra_settings'] = array(
        '#type' => 'textarea',
        '#title' => t('Lock extra settings'),
        '#default_value' => $config->get('auth0_lock_extra_settings'),
        '#description' => t('This should be a valid JSON file. This entire object will be passed to the lock options parameter.')
    );

    $form['actions']['#type'] = 'actions';
    $form['actions']['submit'] = array(
      '#type' => 'submit',
      '#value' => $this->t('Save'),
      '#button_type' => 'primary',
    );
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {

    $config = $this->configFactory->getEditable('auth0.settings');
    $config->set('auth0_form_title', $form_state->getValue('auth0_form_title'))
            ->set('auth0_allow_signup', $form_state->getValue('auth0_allow_signup'))
            ->set('auth0_widget_cdn', $form_state->getValue('auth0_widget_cdn'))
            ->set('auth0_requires_verified_email', $form_state->getValue('auth0_requires_verified_email'))
            ->set('auth0_login_css', $form_state->getValue('auth0_login_css'))
            ->set('auth0_lock_extra_settings', $form_state->getValue('auth0_lock_extra_settings'))
            ->save();
  }
}
