<?php namespace HenriSt\OpenLdapAuth;

use HenriSt\OpenLdapAuth\Helpers\Ldap;
use HenriSt\OpenLdapAuth\Helpers\LdapException;
use HenriSt\OpenLdapAuth\Helpers\GroupHelper;

class LdapGroup implements \JsonSerializable {
	/**
	 * LDAP-object
	 * @var \HenriSt\OpenLdapAuth\Helpers\Ldap
	 */
	protected $ldap;

	/**
	 * All of the group's attributes.
	 *
	 * @var array
	 */
	protected $attributes;

	/**
	 * Attributes updated but not stored
	 *
	 * @var array
	 */
	protected $attributes_updated = array();

	/**
	 * New group object not stored?
	 *
	 * @var bool
	 */
	protected $is_new = false;

	/**
	 * Members of the group
	 *
	 * @var array for username strings
	 */
	protected $members;

	/**
	 * Members of the group (objects)
	 *
	 * @var array of users
	 */
	protected $memberObjs;

	/**
	 * Helper
	 *
	 * @var GroupHelper
	 */
	protected $helper;

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
		$this->helper = $this->ldap->getGroupHelper();
		$this->is_new = empty($attributes);
	}

	/**
	 * Store changes to server, including new groups
	 */
	public function store()
	{
		$this->ldap->bindPrivileged();
		
		// don't have groupname?
		if (!isset($this->name))
		{
			throw new LdapException("Can't store group without groupname.");
		}

		// new group?
		if ($this->is_new)
		{
			if ($this->helper->find($this->name))
			{
				throw new LdapException("Group already exists.");
			}

			$skel = array(
				'objectClass' => array(
					'posixGroup'
				),
				'cn' => $this->name,
				'gidNumber' => $this->helper->getNextID(),
				'description' => 'Group account'
			);

			foreach (array_keys($this->attributes_updated, 'name') as $key)
			{
				unset($this->attributes_updated[$key]);
			}
			
			// create this object
			if (!ldap_add($this->ldap->get_connection(), $this->get_dn(), $skel))
			{
				throw new LdapException("Unknown error.");
			}
			$this->is_new = false;
		}

		if ($this->attributes_updated)
		{
			$new = array();
			foreach ($this->attributes_updated as $field)
			{
				if (!isset($new[$field]))
				{
					$new[$field] = $this->attributes[$field];
				}
			}

			if (!ldap_mod_replace($this->ldap->get_connection(), $this->get_dn(), $new))
			{
				throw new LdapException("Unknown error.");
			}
			$this->attributes_updated = array();
		}
	}

	public function noMembers()
	{
		$this->members = null;
	}

	/**
	 * Set list of members
	 */
	public function setMembers($list)
	{
		$this->members = $list;
	}

	/**
	 * Get list of members
	 */
	public function getMembers()
	{
		if (is_null($this->members))
		{
			// not loaded
			throw new Exception("Not implemented");
		}

		return (array) $this->members;
	}

	public function getMemberObjs()
	{
		if (is_null($this->memberObjs))
		{
			$this->helper->loadUsers($this);
		}

		return (array) $this->memberObjs;
	}

	public function clearMemberObjs()
	{
		$this->memberObjs = null;
	}

	public function addMemberObj(LdapUser $user)
	{
		if (is_null($this->memberObjs))
			$this->memberObjs = array();

		$this->memberObjs[] = $user;
	}

	/**
	 * Get DN for the object
	 *
	 * @return string
	 */
	public function get_dn()
	{
		return sprintf("%s=%s,%s",
			$this->helper->field('unique_id'),
			Ldap::escape_string($this->name),
			$this->ldap->config['group_dn']
		);
	}

	/**
	 * Dynamically access the group's attributes.
	 *
	 * @param  string  $key
	 * @return mixed
	 */
	public function __get($key)
	{
		return $this->attributes[$key];
	}

	/**
	 * Dynamically set an attribute on the group.
	 *
	 * @param  string  $key
	 * @param  mixed   $value
	 * @return void
	 */
	public function __set($key, $value)
	{
		$this->attributes[$key] = $value;
		$this->attributes_updated[] = $key;
	}

	/**
	 * Dynamically check if a value is set on the group.
	 *
	 * @param  string  $key
	 * @return bool
	 */
	public function __isset($key)
	{
		return isset($this->attributes[$key]);
	}

	/**
	 * Dynamically unset a value on the group.
	 *
	 * @param  string  $key
	 * @return bool
	 */
	public function __unset($key)
	{
		unset($this->attributes[$key]);
	}

	/**
	 * Array-representation
	 *
	 * @param array field to ignore
	 * @param int depth (0 = no user details, 1 = usernames only, 2 = user objects)
	 */
	public function toArray(array $except = array())
	{
		$d = $this->attributes;
		foreach ($except as $e)
			unset($d[$e]);

		// members
		if (!is_null($this->memberObjs) && !in_array("members", $except))
		{
			$d = array_merge($d, array("members" => $this->getMemberObjs()));
		}
		elseif (!is_null($this->members) && !in_array("members", $except))
		{
			$d = array_merge($d, array("members" => $this->getMembers()));
		}

		return $d;
	}

	/**
	 * Make array for JSON
	 *
	 * @return array
	 */
	public function jsonSerialize()
	{
		return $this->toArray();
	}
}
