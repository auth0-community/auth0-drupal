<?php global $base_root; ?>
<?php
$params = array(
    'domain' => filter_var(variable_get("auth0_domain"), FILTER_SANITIZE_STRING),
    'chrome' => true,
    'clientID' => filter_var(variable_get("auth0_client_id"), FILTER_SANITIZE_STRING),
    'callbackURL' => filter_var("$base_root/auth0/callback", FILTER_VALIDATE_URL),
    'state' => filter_var(uniqid(), FILTER_SANITIZE_STRING),
    'showSignup' => filter_var(variable_get("auth0_allow_signup"), FILTER_VALIDATE_BOOLEAN)
);

$params = array(
    'domain' => filter_var(variable_get("auth0_domain"), FILTER_SANITIZE_STRING),
    'chrome' => true,
    'clientID' => filter_var(variable_get("auth0_client_id"), FILTER_SANITIZE_STRING),
    'callbackURL' => filter_var("$base_root/auth0/callback", FILTER_VALIDATE_URL),
    'state' => filter_var(variable_get('$state'), FILTER_SANITIZE_STRING),
    'showSignup' => filter_var(variable_get("auth0_allow_signup"), FILTER_VALIDATE_BOOLEAN)
);

?>

<script id="auth0" src="<?php echo filter_var(variable_get('auth0_widget_cdn'), FILTER_VALIDATE_URL);?>"></script>
<script type="text/javascript">

    var widget = new Auth0Widget(<?php echo json_encode(array_filter($params)); ?>);

    widget.signin({
        container:      'auth0-login-form',
        scope: 'openid profile'
    });

</script>

<style type="text/css">
<?php echo variable_get("auth0_login_css")?>
</style>

<div id="auth0-login-form" style=" min-height: 440px;"></div>