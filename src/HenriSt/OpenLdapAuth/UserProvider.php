<?php namespace HenriSt\OpenLdapAuth;

use Illuminate\Database\Connection;
use Illuminate\Hashing\HasherInterface;
use Illuminate\Auth;
use HenriSt\OpenLdapAuth\Helpers\Ldap;

class UserProvider implements Auth\UserProviderInterface {
	/**
	 * The LDAP-object
	 * @var \HenriSt\OpenLdapAuth\Helpers\Ldap
	 */
	protected $ldap;

	/**
	 * Create a new user provider.
	 *
	 * @return void
	 */
	public function __construct(Ldap $ldap)
	{
		$this->ldap = $ldap;
	}

	/**
	 * Retrieve a user by their unique identifier.
	 *
	 * @param  mixed  $identifier
	 * @return \HenriSt\OpenLdapAuth\LdapUser|null
	 */
	public function retrieveById($identifier)
	{
		$user = $this->ldap->get_user_details($identifier);
		if (!is_null($user))
		{
			return new LdapUser($user, $this->ldap);
		}
	}

	/**
	 * Retrieve a user by the given credentials.
	 *
	 * @param  array  $credentials
	 * @return \Illuminate\Auth\UserInterface|null
	 */
	public function retrieveByCredentials(array $credentials)
	{
		// TODO: check by other credentials

		$user = $this->ldap->get_user_details($credentials['username']);
		if (!is_null($user))
		{
			return new LdapUser($user, $this->ldap);
		}

/*
		$user = $this->retrieveById($credentials['username']);
		if (!is_null($user))
		{
			return $user;
			//return new LdapUser($user, $this->ldap);
		}*/
	}

	/**
	 * Validate a user against the given credentials.
	 *
	 * @param  \Illuminate\Auth\UserInterface  $user
	 * @param  array  $credentials
	 * @return bool
	 */
	public function validateCredentials(Auth\UserInterface $user, array $credentials)
	{
		return $this->ldap->bind($credentials['username'], $credentials['password']);
	}

}