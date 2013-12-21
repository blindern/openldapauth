<?php namespace HenriSt\OpenLdapAuth\Helpers;

class Ldap {
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
	protected $config;

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
	public function bind($user, $pass)
	{
		$this->connect();
		$user_dn = $this->get_bind_dn($user);
		if (@ldap_bind($this->conn, $user_dn, $pass))
		{
			$this->bound_as = $user;
			return true;
		}
		return false;
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
	 * Get user details
	 * @return array|null
	 */
	public function get_user_details($user)
	{
		$this->connect();
		$fields = array_values($this->config['user_fields']);

		$entry = @ldap_read($this->conn, $this->get_bind_dn($user), 'objectClass=*', $fields);
		$info = @ldap_get_entries($this->conn, $entry);

		if ($info['count'] > 0)
		{
			// map fields
			$data = array();
			foreach ($this->config['user_fields'] as $from => $to) {
				if (isset($info[0][$to]))
				{
					// NOTE: Only allowes for one value, there may be many
					$data[$from] = $info[0][$to][0];
				}
				else
				{
					$data[$from] = null;
				}
			}

			return $data;
		}
	}

	/**
	 * Get user groups
	 * @param string $user
	 * @return array of groups, empty array if none
	 */
	public function get_user_groups($user)
	{
		$this->connect();

		$check = sprintf("(&(memberUid=%s)(objectclass=posixGroup))", $this->escape_string($user));
		$fields = array("dn", "cn", "description", "gidNumber");
		
		$result = ldap_search($this->conn, $this->config['group_dn'], $check, $fields);
		$entires = ldap_get_entries($this->conn, $result);

		/*$groups = array();
		$groups_sort = array();
		for ($i = 0; $i < $entries['count']; $i++)
		{
			$groups_sort[] = strtolower($entries[$i]['cn'][0]);
			$groups[] = array("Ldapgroup", $entries[$i]['cn'][0]);
		}
		array_multisort($groups_sort, $groups);*/

		$groups = array();
		for ($i = 0; $i < $entries['count']; $i++)
		{
			$groups[] = $entries[$i]['cn'][0];
		}

		return $groups;
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
	protected static function escape_string($string)
	{
		// Make the string LDAP compliant by escaping *, (, ) , \ & NUL
		return str_replace(
			array( "\\", "(", ")", "*", "\x00" ),
			array( "\\5c", "\\28", "\\29", "\\2a", "\\00" ),
			$string
			);
	}
}