<?php namespace HenriSt\OpenLdapAuth\Helpers;

use HenriSt\OpenLdapAuth\Helpers\Ldap;
use HenriSt\OpenLdapAuth\Helpers\CommonHelper;
use HenriSt\OpenLdapAuth\LdapUser;

class UserHelper extends CommonHelper {
	protected $type = 'user';
	protected $objectClass = 'posixAccount';

	/**
	 * Load groups for collection of users
	 *
	 * @param array users
	 * @return void
	 */
	public function fetchGroups($users)
	{
		$list = array();
		foreach ($users as $user)
		{
			$list[] = sprintf('(%s=%s)', $this->ldap->config['group_fields']['members'], Ldap::escape_string($user->username));
		}

		$groups = $this->ldap->getGroupHelper()->getByFilter(sprintf('(|%s)', implode("", $list)), 1);

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
			foreach ($group->getMembers() as $member)
			{
				if (isset($map[$member]))
				{
					$map[$member]->appendGroup($group);
				}
			}
		}
	}

	/**
	 * Get info about users (all by default)
	 * Sorts the list by realnames
	 *
	 * @param string $search_by LDAP-string for searching, eg. (uid=*), defaults to all users
	 * @return array of LdapUser
	 */
	public function getByFilter($search_by = null)
	{
		// handle search by
		$search_by = empty($search_by) ? '(uid=*)' : $search_by;

		// handle fields
		$user_fields = $this->ldap->config['user_fields'];
		$fields = array_values($user_fields);
		/*if (!empty($extra_fields))
		{
			if (!is_array($extra_fields))
			{
				throw new \Exception("Extra fields is not an array.");
			}

			$fields = array_merge($fields, $extra_fields);
			foreach ($extra_fields as $field)
			{
				$user_fields[$field] = $field;
			}
		}*/

		// retrieve info from LDAP
		$r = ldap_search($this->ldap->get_connection(), $this->ldap->config['user_dn'], $search_by, $fields);
		$e = ldap_get_entries($this->ldap->get_connection(), $r);

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
			$users[] = new LdapUser($row, $this->ldap);
		}

		// sort by realname
		array_multisort($users_names, $users);

		return $users;
	}
}