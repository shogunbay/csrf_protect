<?php
/**
 * Description of CSRFProtect
 *
 * with this class you can add a token to a form
 *
 * @author bd
 */

class CSRFProtect {
	
	// the name of the token field
	const FIELDNAME = "tok";

	protected static $doRefererCheck = TRUE;
	protected static $ttl = 7200;
	protected static $token_time;
	protected static $clear = TRUE;
	// which Requests should be accepted? -> POST/GET
	protected static $acceptGet = FALSE;

	/*
	 * this method gets a hidden field with a generated token
	 */
	public static function getField(){
		self::garbageCollector();
		$tok = self::generateToken();
		return '<input type="hidden" name="' . self::FIELDNAME . '" value="' . $tok . '" />';
	}

	/**
	 * generates a token with sha512
	 * with the doOriginCheck we can take additionaly the remote_addr and the http_user_agent to generate the token
	 * @return type token
	 */
	protected static function generateToken(){
		$extra = self::$doRefererCheck ? sha1( $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] ) : '';
		$time = time();
		$tok = hash('sha512', $extra . mt_rand(0, 1000000));
		$_SESSION['token'][$tok] = $time;

		return $tok;
	}

	/**
	 * validates a token
	 * @return boolean
	 */
	public static function validateToken(){
		if( self::checkToken() ){
			return true;
		}
		self::getErrorLog();
		return false;
    }

	/**
	 * checks for the right token and additionaly checks the time to live from the token
	 * @param type $clear unset the session
	 * @return boolean
	 */
	protected static function checkToken($clear = NULL){
		if(!$clear){
			$clear = self::$clear;
		}

		if(!self::$acceptGet){
			$token = $_POST[self::FIELDNAME];
		}else{
			$token = $_REQUEST[self::FIELDNAME];
		}
		
		$valid = false;
        $posted = isset($token) ? $token : '';

        if (!empty($posted)) {
			self::$token_time = $_SESSION['token'][$posted];
            if (isset(self::$token_time)) {
                 if (self::checkTimeout()) {
                    $valid = true;
                 }
                 if ($clear) unset($_SESSION['token'][$posted]);
            }
        }
        return $valid;
	}

	public static function setRefererCheck( $val ){
		self::$doRefererCheck = $val;
	}

	public static function setAcceptGet( $val ){
		self::$acceptGet = $val;
	}
	/**
	 *
	 * @param type $token_time when the token was posted
	 * @param type $ttl time to live
	 * @return type
	 */
	private static function checkTimeout($token_time = NULL, $ttl = NULL ){
		if(!$ttl){
			$ttl = self::$ttl;
		}
		if(!$token_time){
			$token_time = self::$token_time;
		}
		return ($token_time >= time() - $ttl);
	}

	/**
	 * error handling, when a csrf-attack was found
	 */
	private static function getErrorLog(){
		die('Beim senden des Formulars ist etwas schiefgelaufen');
	}
	/**
	 *	garbage collector for session variables
	 */
	private static function garbageCollector(){
		$garbage_time = 7200;
		if( isset($_SESSION['token']) ){
			foreach( $_SESSION['token'] as $token ){
				if( $token < (time() - $garbage_time) ){
					$t = array_search($token,$_SESSION['token']);
					unset( $_SESSION['token'][$t] );
				}
			}
		}
	}
}
