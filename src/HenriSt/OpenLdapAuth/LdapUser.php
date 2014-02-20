<?php namespace HenriSt\OpenLdapAuth;

use Illuminate\Auth;
use HenriSt\OpenLdapAuth\Helpers\Ldap;

class LdapUser implements Auth\UserInterface {
	protected static $ldap_s;

	public static function init()
	{
		if (static::$ldap_s) return;

		// set up LDAP
		$config = app()->config['auth']['ldap'];
		static::$ldap_s = new Ldap($config);
	}

	/**
	 * Find user
	 *
	 * @return LdapUser
	 */
	public static function find($username)
	{
		static::init();
		$users = static::$ldap_s->get_users_by_usernames(array($username));
		if ($users[0]) return $users[0];
	}

	/**
	 * Get all users
	 *
	 * @return array
	 */
	public static function all($get_groups = false)
	{
		static::init();

		$users = static::$ldap_s->get_users();
		
		// get groups?
		if ($get_groups)
		{
			static::fetchGroups($users);
		}

		return $users;
	}

	/**
	 * Load groups for collection of users
	 *
	 * @param array users
	 * @return void
	 */
	public static function fetchGroups($users)
	{
		static::init();

		$list = array();
		foreach ($users as $user)
		{
			$list[] = sprintf('(%s=%s)', static::$ldap_s->config['group_fields']['members'], Ldap::escape_string($user->username));
		}

		$groups = static::$ldap_s->get_groups(true, sprintf('(|%s)', implode("", $list)));

		// reset groups data and make map
		$map = array();
		foreach ($users as $user)
		{
			$user->initGroups();
			$map[$user->username] = $user;
		}

		// append groups to users
		foreach ($groups as $group)
		{
			foreach ($group['members'] as $member)
			{
				if (isset($map[$member]))
				{
					$map[$member]->appendGroup($group);
				}
			}
		}
	}

	/**
	 * LDAP-object
	 * @var \HenriSt\OpenLdapAuth\Helpers\Ldap
	 */
	protected $ldap;

	/**
	 * All of the user's attributes.
	 *
	 * @var array
	 */
	protected $attributes;

	/**
	 * Group list
	 *
	 * @var array
	 */
	protected $groups;

	/**
	 * Create a new generic User object.
	 *
	 * @param  array  $attributes
	 * @return void
	 */
	public function __construct(array $attributes, Ldap $ldap)
	{
		$this->attributes = $attributes;
		$this->ldap = $ldap;
	}

	/**
	 * Get the unique identifier for the user.
	 *
	 * @return mixed
	 */
	public function getAuthIdentifier()
	{
		return $this->attributes['username'];
	}

	/**
	 * Get the password for the user.
	 *
	 * @return string
	 */
	public function getAuthPassword()
	{
		// Not available
		return null;
		//return $this->attributes['password'];
	}

	/**
	 * Get user groups
	 *
	 * @param boolean $refresh Reload cache?
	 * @return array of groups
	 */
	public function groups($refresh = false)
	{
		if ($refresh || is_null($this->groups))
		{
			$this->groups = $this->ldap->get_user_groups($this->username);
		}
		
		return $this->groups;
	}

	/**
	 * Check if user is in a group
	 *
	 * @param string $group Name of group
	 * @param boolean $superadmin Allow superadmin (in group if superadmin)
	 * @return boolean
	 */
	public function in_group($group, $allow_superadmin = true)
	{
		$groups = $this->groups();

		$allow_superadmin = $allow_superadmin ? $this->ldap->config['superadmin_group'] : null;
		foreach ($groups as $row)
		{
			if ($row['name'] == $group || $row['name'] == $allow_superadmin)
			{
				return true;
			}
		}

		return false;
	}

	/**
	 * Initialize groups array
	 */
	protected function initGroups()
	{
		$this->groups = array();
	}

	/**
	 * Assign group to user internally
	 */
	protected function appendGroup($group)
	{
		$this->groups[] = $group;
	}

	/**
	 * Dynamically access the user's attributes.
	 *
	 * @param  string  $key
	 * @return mixed
	 */
	public function __get($key)
	{
		return $this->attributes[$key];
	}

	/**
	 * Dynamically set an attribute on the user.
	 *
	 * @param  string  $key
	 * @param  mixed   $value
	 * @return void
	 */
	public function __set($key, $value)
	{
		$this->attributes[$key] = $value;
	}

	/**
	 * Dynamically check if a value is set on the user.
	 *
	 * @param  string  $key
	 * @return bool
	 */
	public function __isset($key)
	{
		return isset($this->attributes[$key]);
	}

	/**
	 * Dynamically unset a value on the user.
	 *
	 * @param  string  $key
	 * @return bool
	 */
	public function __unset($key)
	{
		unset($this->attributes[$key]);
	}

	/**
	 * Convert to array
	 *
	 * @param array Fields to ignore
	 * @return array
	 */
	public function toArray(array $except = array())
	{
		$d = $this->attributes;
		foreach ($except as $e)
			unset($d[$e]);

		// groups?
		if ($this->groups)
		{
			$groups = array();
			foreach ($this->groups as $group)
			{
				$groups[] = $group['name'];
			}

			return array_merge($d, array("groups" => $groups));
		}

		return $d;
	}

	/**
	 * Check for same user
	 *
	 * @param LdapUser
	 * @return bool
	 */
	public function isSame(LdapUser $user)
	{
		return $this->username == $user->username;
	}
}
