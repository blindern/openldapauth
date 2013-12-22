<?php namespace HenriSt\OpenLdapAuth;

use Illuminate\Auth;
use HenriSt\OpenLdapAuth\Helpers\Ldap;

class LdapUser implements Auth\UserInterface {

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

}
