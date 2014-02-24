<?php namespace HenriSt\OpenLdapAuth\Helpers;

use HenriSt\OpenLdapAuth\LdapUser;
use HenriSt\OpenLdapAuth\Helpers\GroupHelper;
use HenriSt\OpenLdapAuth\Helpers\UserHelper;

class Ldap {
	/**
	 * Create connection
	 */
	public static function forge()
	{
		$config = app()->config['auth']['ldap'];
		return new static($config);
	}

	/**
	 * LDAP-connection
	 */
	protected $conn;

	/**
	 * User bound as
	 */
	protected $bound_as;

	/**
	 * Configuration
	 */
	public $config;

	/**
	 * UserHelper-object
	 *
	 * @var UserHelper
	 */
	public $userhelper;

	/**
	 * GroupHelper-object
	 *
	 * @var GroupHelper
	 */
	public $grouphelper;

	/**
	 * Initializer
	 */
	public function __construct($config)
	{
		$this->config = $config;
	}

	/**
	 * Connect to LDAP-server
	 * @return void
	 */
	public function connect()
	{
		// don't run if connected
		if ($this->conn) return;

		$this->conn = ldap_connect($this->config['server']);
		if (!$this->conn)
		{
			throw new LdapException("Cannot connect to {$this->config['server']}.");
		}

		ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);

		// tls?
		if (!empty($this->config['tls']))
		{
			if (!ldap_start_tls($this->conn))
			{
				throw new LdapException("Could not start TLS to {$this->config['server']}.");
			}
		}
	}

	/**
	 * Test binding to LDAP-server
	 */
	public function bind($user, $pass, $is_dn = false)
	{
		$this->connect();
		$user_dn = $is_dn ? $user : $this->get_bind_dn($user);
		if (@ldap_bind($this->conn, $user_dn, $pass))
		{
			$this->bound_as = $user;
			return true;
		}
		return false;
	}

	/**
	 * Bind as privileged user
	 */
	public function bindPrivileged()
	{
		return $this->bind($this->config['admin_dn'], $this->config['admin_pw'], true);
	}

	/**
	 * Construct user DN for binding
	 */
	public function get_bind_dn($user)
	{
		$user = static::escape_string($user);
		return str_replace("USERNAME", $user, $this->config['bind_dn']);
	}

	/**
	 * Get user helper
	 */
	public function getUserHelper()
	{
		if (!isset($this->userhelper))
			$this->userhelper = new UserHelper($this);
		return $this->userhelper;
	}

	/**
	 * Get group helper
	 */
	public function getGroupHelper()
	{
		if (!isset($this->grouphelper))
			$this->grouphelper = new GroupHelper($this);
		return $this->grouphelper;
	}

	/**
	 * Get user details
	 * @return array|null
	 */
	public function get_user_details($user)
	{
		throw new LdapException("Not to be used.");
	}

	/**
	 * Get user groups
	 * @param string $user
	 * @return array of groups, empty array if none
	 */
	public function get_user_groups($user)
	{
		$this->connect();

		$search_by = sprintf('(%s=%s)', $this->config['group_fields']['members'], static::escape_string($user));
		return $this->getGroupHelper()->getByFilter($search_by, false);
	}

	/**
	 * Get connection
	 * @return LDAP-connection
	 */
	public function get_connection()
	{
		$this->connect();
		return $this->conn;
	}

	/**
	 * Returns a string which has the chars *, (, ), \ & NUL escaped to LDAP compliant
	 * syntax as per RFC 2254
	 * Thanks and credit to Iain Colledge for the research and function.
	 * (from MediaWiki LdapAuthentication-extension)
	 *
	 * @param string $string
	 * @return string
	 * @access private
	 */
	public static function escape_string($string)
	{
		// Make the string LDAP compliant by escaping *, (, ) , \ & NUL
		return str_replace(
			array( "\\", "(", ")", "*", "\x00" ),
			array( "\\5c", "\\28", "\\29", "\\2a", "\\00" ),
			$string
			);
	}
}

class LdapException extends \Exception {}