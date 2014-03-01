<?php namespace HenriSt\OpenLdapAuth\Helpers;

use HenriSt\OpenLdapAuth\Helpers\Ldap;
use HenriSt\OpenLdapAuth\Helpers\CommonHelper;
use HenriSt\OpenLdapAuth\LdapGroup;

class GroupHelper extends CommonHelper {
	protected $type = 'group';
	protected $objectClass = 'posixGroup';

	/**
	 * Load users for groups
	 */
	public function loadUsers($groups)
	{
		if (!is_array($groups)) $groups = array($groups);

		// get users
		$names = array();
		foreach ($groups as $group)
		{
			foreach ($group->getMembers() as $username)
			{
				$names[] = $username;
			}
		}
		$names = array_unique($names);
		$users = $this->ldap->getUserHelper()->getByNames($names);

		// create username map
		$map = array();
		foreach ($users as $user)
		{
			$map[$user->unique_id] = $user;
		}

		// add to groups
		foreach ($groups as $group)
		{
			$realnames = array();
			$group->clearMemberObjs();
			foreach ($group->getMembers() as $username)
			{
				if (isset($map[$username]))
				{
					$realnames[] = $map[$username]->realname;
					$group->addMemberObj($map[$username]); // we actually sort twice, once when fetching users, optimize?
				}
			}

			if ($realnames) $group->sortMemberObjs($realnames);
		}
	}

	/**
	 * Get groups list
	 * Sorts the list by group names
	 *
	 * @param string $search_by LDAP-string for searching, eg. (cn=admin), defaults to all groups
	 * @return array
	 */
	// get_groups
	public function getByFilter($search_by = null)
	{
		// handle search by
		$s = '(objectClass=posixGroup)';
		if (!empty($search_by))
		{
			$s = sprintf('(&%s%s)', $s, $search_by);
		}

		$fields = array(
			$this->field('unique_id'),
			$this->field('id'),
			$this->field('name'),
			$this->field('description'),
			$this->field('members')
		);
		
		// retrieve info from LDAP
		$r = ldap_search($this->ldap->get_connection(), $this->ldap->config['group_dn'], $s, $fields);
		$e = ldap_get_entries($this->ldap->get_connection(), $r);

		// ldap_get_entries makes attributes lowercase
		$group_fields = $this->ldap->config['group_fields'];
		foreach ($group_fields as &$field)
		{
			$field = strtolower($field);
		}

		$groups = array();
		$groups_names = array();
		for ($i = 0; $i < $e['count']; $i++)
		{
			// skip some groups
			if (in_array($e[$i][$group_fields['unique_id']][0], $this->ldap->config['groups_ignore']))
			{
				continue;
			}

			$group = new LdapGroup(array(
				"unique_id" => $e[$i][$group_fields['unique_id']][0],
				"id" => $e[$i][$group_fields['id']][0],
				"name" => $e[$i][$group_fields['name']][0],
				"description" => isset($e[$i][$group_fields['description']]) ? $e[$i][$group_fields['description']][0] : null,
			), $this->ldap);

			// members
			$members = array();
			$mf = $group_fields['members'];
			if (!empty($e[$i][$mf]))
			{
				for ($j = 0; $j < $e[$i][$mf]['count']; $j++)
				{
					$uid = $e[$i][$mf][$j];
					$members[] = $uid;
				}
			}

			$group->setMembers($members);
			
			$groups[] = $group;
			$groups_names[] = $group->name;
		}

		// sort by name
		array_multisort($groups_names, $groups);

		return $groups;
	}
}
