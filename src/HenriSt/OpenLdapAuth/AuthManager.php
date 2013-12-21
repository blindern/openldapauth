<?php namespace HenriSt\OpenLdapAuth;

use Illuminate\Support\Manager;
use Illuminate\Auth\Guard;
use HenriSt\OpenLdapAuth\Helpers\Ldap;

class AuthManager extends Manager {

	/**
	 * Create a new driver instance.
	 *
	 * @param  string  $driver
	 * @return mixed
	 */
	protected function createDriver($driver)
	{
		$guard = parent::createDriver($driver);

		// When using the remember me functionality of the authentication services we
		// will need to be set the encryption instance of the guard, which allows
		// secure, encrypted cookie values to get generated for those cookies.
		$guard->setCookieJar($this->app['cookie']);

		$guard->setDispatcher($this->app['events']);

		return $guard->setRequest($this->app->refresh('request', $guard, 'setRequest'));
	}

	/**
	 * Call a custom driver creator.
	 *
	 * @param  string  $driver
	 * @return mixed
	 */
	protected function callCustomCreator($driver)
	{
		$custom = parent::callCustomCreator($driver);

		if ($custom instanceof Guard) return $custom;

		return new Guard($custom, $this->app['session.store']);
	}

	/**
	 * Create an instance of the database driver.
	 *
	 * @return \Illuminate\Auth\Guard
	 */
	public function createLdapDriver()
	{
		$provider = $this->createLdapProvider();

		return new Guard($provider, $this->app['session.store']);
	}

	/**
	 * Create an instance of the database user provider.
	 *
	 * @return \HenriSt\OpenLdapAuth\UserProvider
	 */
	protected function createLdapProvider()
	{
		$ldap = new Ldap($this->app['config']['auth']['ldap']);

		return new UserProvider($ldap);
	}

	/**
	 * Get the default authentication driver name.
	 *
	 * @return string
	 */
	protected function getDefaultDriver()
	{
		return $this->app['config']['auth.driver'];
	}

}