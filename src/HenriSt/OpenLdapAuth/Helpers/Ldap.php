<?php namespace HenriSt\OpenLdapAuth\Helpers;

use HenriSt\OpenLdapAuth\LdapUser;

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
	public $config;

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
		throw new LdapException("Not to be used.");
		$result = $this->get_users_by_usernames(array($user));
		if ($result)
		{
			return $result[0];
		}
	}

	/**
	 * Get details about a user collection
	 * @param array list of usernames
	 * @return array(array|null user, ..)
	 */
	public function get_users_by_usernames(array $users, $extra_fields = array())
	{
		$list = array();
		foreach ($users as $user)
		{
			$list[] = sprintf('(%s=%s)', $this->config['user_fields']['unique_id'], Ldap::escape_string($user));
		}
		$filter = sprintf('(|%s)', implode("", $list));

		return $this->get_users($filter, $extra_fields);
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
		return $this->get_groups(false, $search_by);
	}

	/**
	 * Get connection
	 * @return LDAP-connection
	 */
	public function get_connection()
	{
		return $this->conn;
	}

	/**
	 * Get info about users (all by default)
	 * Sorts the list by realnames
	 *
	 * @param string $search_by LDAP-string for searching, eg. (uid=*), defaults to all users
	 * @param array $extra_fields
	 * @return array of LdapUser
	 */
	public function get_users($search_by = null, $extra_fields = array())
	{
		$this->connect();

		// handle search by
		$search_by = empty($search_by) ? '(uid=*)' : $search_by;

		// handle fields
		$user_fields = $this->config['user_fields'];
		$fields = array_values($user_fields);
		if (!empty($extra_fields))
		{
			if (!is_array($extra_fields))
			{
				throw new Exception("Extra fields is not an array.");
			}

			$fields = array_merge($fields, $extra_fields);
			foreach ($extra_fields as $field)
			{
				$user_fields[$field] = $field;
			}
		}

		// retrieve info from LDAP
		$r = ldap_search($this->conn, $this->config['user_dn'], $search_by, $fields);
		$e = ldap_get_entries($this->conn, $r);

		// ldap_get_entries makes attributes lowercase
		foreach ($user_fields as &$field)
		{
			$field = strtolower($field);
		}

		$users = array();
		$users_names = array();
		for ($i = 0; $i < $e['count']; $i++)
		{
			// map fields
			$row = array();
			foreach ($user_fields as $map => $to)
			{
				$to = strtolower($to); // ldap_get_entries makes attributes lowercase
				if (isset($e[$i][$to]))
				{
					// NOTE: Only allowes for one value, there may be many
					$row[$map] = $e[$i][$to][0];
				}
				else
				{
					$row[$map] = null;
				}
			}

			$users_names[] = strtolower($row['realname']);
			$users[] = new LdapUser($row, $this);
		}

		// sort by realname
		array_multisort($users_names, $users);

		return $users;
	}

	/**
	 * Get groups list
	 * Sorts the list by group names
	 *
	 * @param bool $get_members Create list of members
	 * @param string $search_by LDAP-string for searching, defaults to all groups
	 * @return array
	 */
	public function get_groups($get_members = true, $search_by = null)
	{
		$this->connect();

		// handle search by
		$s = '(objectClass=posixGroup)';
		if (!empty($search_by))
		{
			$s = sprintf('(&%s%s)', $s, $search_by);
		}

		$fields = array(
			$this->config['group_fields']['unique_id'],
			$this->config['group_fields']['id'],
			$this->config['group_fields']['name']
		);
		if ($get_members)
		{
			$fields[] = $this->config['group_fields']['members'];
		}

		// retrieve info from LDAP
		$r = ldap_search($this->conn, $this->config['group_dn'], $s, $fields);
		$e = ldap_get_entries($this->conn, $r);

		// ldap_get_entries makes attributes lowercase
		$group_fields = $this->config['group_fields'];
		foreach ($group_fields as &$field)
		{
			$field = strtolower($field);
		}

		$groups = array();
		$groups_names = array();
		for ($i = 0; $i < $e['count']; $i++)
		{
			// skip some groups
			if (in_array($e[$i][$group_fields['unique_id']][0], $this->config['groups_ignore']))
			{
				continue;
			}

			$group = array(
				"unique_id" => $e[$i][$group_fields['unique_id']][0],
				"id" => $e[$i][$group_fields['id']][0],
				"name" => $e[$i][$group_fields['name']][0]
			);

			if ($get_members)
			{
				$group['members'] = array();
				$mf = $group_fields['members'];
				if (!empty($e[$i][$mf]))
				{
					for ($j = 0; $j < $e[$i][$mf]['count']; $j++)
					{
						$uid = $e[$i][$mf][$j];
						$group['members'][] = $uid;
					}
				}
			}

			$groups[$group['unique_id']] = $group;
			$groups_names[] = $group['name'];
		}

		// sort by name
		array_multisort($groups_names, $groups);

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