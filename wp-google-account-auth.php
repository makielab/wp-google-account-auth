<?php
/*
Plugin Name: WP Google Account Auth
Version: 0.0.1
Plugin URI: http://github.com/lpetre/wp-google-account-auth
Description: WP Google Account Auth is a wordpress plugin that allows wordpress to authenticate against a google account.
Author: Luke Petre
Author URI: http://github.com/lpetre
*/
require 'openid.php';

add_action( 'login_head', 'googleaccount_wp_login_head');
add_action( 'login_form', 'googleaccount_wp_login_form');
add_action( 'authenticate', 'googleaccount_authenticate' );


/**
 * Authenticate user to WordPress using OpenID.
 *
 * @param mixed $user authenticated user object, or WP_Error or null
 */
function googleaccount_authenticate($user) {

	if (array_key_exists('googleaccount_login', $_REQUEST))
	{
		$url = get_option('siteurl') . '/wp-login.php';

    	$openid = new LightOpenID($url);
	    if(!$openid->mode) {
	    	$openid->realm = get_option('siteurl');
	    	$openid->returnUrl = add_query_arg( array( 
				'googleaccount_login' => 1,
				'googleaccount_nonce' => wp_create_nonce('googleaccount_' . md5($url)), 
				'redirect_to' => array_key_exists('redirect_to', $_REQUEST) ? $_REQUEST['redirect_to'] : null,
				), $url);
	    	$openid->required = array('contact/email');
	        $openid->identity = 'https://www.google.com/accounts/o8/id';
	        wp_redirect($openid->authUrl());
	        exit;
	    }
	    elseif($openid->mode == 'cancel') 
	    {
			return new WP_Error( 'googleaccount_login_error', 'User has canceled authentication!' );
	    }
	    elseif(!$openid->validate())
	    {
			return new WP_Error( 'googleaccount_login_error', 'User has not logged in.' );
	    }
		elseif(!wp_verify_nonce($_REQUEST['googleaccount_nonce'], 'googleaccount_' . md5($url)))
		{
			return new WP_Error('googleaccount_login_error', 'Error during OpenID authentication.  Please try again. (invalid nonce)');
		}

	   	$attr = $openid->getAttributes();
	   	$found_user = get_user_by('email', $attr['contact/email']);
	   	if ( !$found_user ) 
	   	{
			return new WP_Error('googleaccount_login_error', __('<strong>ERROR</strong>: No user with that email address: ....'));
		}

		return new WP_User($found_user->ID);
	}

	return $user;
}

function googleaccount_error($msg) {
	error_log('[GoogleAccount] ' . $msg);
}

function googleaccount_debug($msg) {
	if (defined('WP_DEBUG') && WP_DEBUG) {
		googleaccount_error($msg);
	}
}

/**
 * Add style and script to login page.
 */
function googleaccount_wp_login_head() {
	echo '<link rel="stylesheet" href="'.plugins_url('wp-google-account-auth/auth-buttons.css').'"><style>
		label[for=user_login], label[for=user_pass] { display: none; } 
		#user_login, #user_pass, .submit, .forgetmenot, #nav { display: none; }
		</style>';
}

/**
 * Add OpenID input field to wp-login.php
 *
 * @action: login_form
 **/
function googleaccount_wp_login_form() {
	echo '<input type="hidden" name="googleaccount_login"/>
	<button class="btn-auth btn-google large">Login with Google</button>';
}
?>