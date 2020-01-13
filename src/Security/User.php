<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * User authentication and authorization.
 *
 * @property-read bool $loggedIn
 * @property-read IIdentity $identity
 * @property-read mixed $id
 * @property-read array $roles
 * @property-read int $logoutReason
 * @property   IAuthenticator $authenticator
 * @property   IAuthorizator $authorizator
 */
class User
{
	use Nette\SmartObject;

	/** @deprecated */
	public const
		MANUAL = IUserStorage::MANUAL,
		INACTIVITY = IUserStorage::INACTIVITY;

	/** @var string  default role for unauthenticated user */
	public $guestRole = 'guest';

	/** @var string  default role for authenticated user without own identity */
	public $authenticatedRole = 'authenticated';

	/** @var callable[]  function (User $sender): void; Occurs when the user is successfully logged in */
	public $onLoggedIn;

	/** @var callable[]  function (User $sender): void; Occurs when the user is logged out */
	public $onLoggedOut;

	/** @var IUserStorage Session storage for current user */
	private $storage;

	/** @var IAuthenticator|null */
	private $authenticator;

	/** @var IAuthorizator|null */
	private $authorizator;

	/** @var IIdentity|null|false  false means undefined */
	private $identity = false;

	/** @var bool|null */
	private $authenticated;


	public function __construct(IUserStorage $storage, IAuthenticator $authenticator = null, IAuthorizator $authorizator = null)
	{
		$this->storage = $storage;
		$this->authenticator = $authenticator;
		$this->authorizator = $authorizator;
	}


	final public function getStorage(): IUserStorage
	{
		return $this->storage;
	}


	/********************* Authentication ****************d*g**/


	/**
	 * Conducts the authentication process. Parameters are optional.
	 * @param  string|IIdentity  $user  name or Identity
	 * @throws AuthenticationException if authentication was not successful
	 */
	public function login($user, string $password = null): void
	{
		$this->logout(true);
		if (!$user instanceof IIdentity) {
			$user = $this->getAuthenticator()->authenticate(func_get_args());
		}
		$this->storage->setIdentity($user);
		$this->storage->setAuthenticated(true);
		$this->identity = $user;
		$this->authenticated = true;
		$this->onLoggedIn($this);
	}


	/**
	 * Logs out the user from the current session.
	 */
	final public function logout(bool $clearIdentity = false): void
	{
		if ($this->isLoggedIn()) {
			$this->onLoggedOut($this);
			$this->storage->setAuthenticated(false);
			$this->authenticated = false;
		}
		if ($clearIdentity) {
			$this->storage->setIdentity(null);
			$this->identity = null;
		}
	}


	/**
	 * Is this user authenticated?
	 */
	final public function isLoggedIn(): bool
	{
		if ($this->authenticated === null) {
			$this->authenticated = $this->storage->isAuthenticated();
		}
		return $this->authenticated;
	}


	/**
	 * Returns current user identity, if any.
	 */
	final public function getIdentity(): ?IIdentity
	{
		if ($this->identity === false) {
			$this->identity = $this->storage->getIdentity();
		}
		return $this->identity;
	}


	/**
	 * Returns current user ID, if any.
	 * @return mixed
	 */
	public function getId()
	{
		$identity = $this->getIdentity();
		return $identity ? $identity->getId() : null;
	}


	/**
	 * Sets authentication handler.
	 * @return static
	 */
	public function setAuthenticator(IAuthenticator $handler)
	{
		$this->authenticator = $handler;
		return $this;
	}


	/**
	 * Returns authentication handler.
	 */
	final public function getAuthenticator(): ?IAuthenticator
	{
		if (func_num_args()) {
			trigger_error(__METHOD__ . '() parameter $throw is deprecated, use getAuthenticatorIfExists()', E_USER_DEPRECATED);
			$throw = func_get_arg(0);
		}
		if (($throw ?? true) && !$this->authenticator) {
			throw new Nette\InvalidStateException('Authenticator has not been set.');
		}
		return $this->authenticator;
	}


	/**
	 * Returns authentication handler.
	 */
	final public function getAuthenticatorIfExists(): ?IAuthenticator
	{
		return $this->authenticator;
	}


	/** @deprecated */
	final public function hasAuthenticator(): bool
	{
		return (bool) $this->authenticator;
	}


	/**
	 * Enables log out after inactivity (like '20 minutes'). Accepts flag IUserStorage::CLEAR_IDENTITY.
	 * @param  string|null  $expire
	 * @param  int  $flags
	 * @return static
	 */
	public function setExpiration($expire, /*int*/$flags = 0)
	{
		$clearIdentity = $flags === IUserStorage::CLEAR_IDENTITY;
		if ($expire !== null && !is_string($expire)) {
			trigger_error("Expiration should be a string like '20 minutes' etc.", E_USER_DEPRECATED);
		}
		if (is_bool($flags)) {
			trigger_error(__METHOD__ . '() second parameter $whenBrowserIsClosed was removed.', E_USER_DEPRECATED);
		}
		if (func_num_args() > 2) {
			$clearIdentity = $clearIdentity || func_get_arg(2);
			trigger_error(__METHOD__ . '() third parameter is deprecated, use flag setExpiration($time, IUserStorage::CLEAR_IDENTITY)', E_USER_DEPRECATED);
		}
		$this->storage->setExpiration($expire, $clearIdentity ? IUserStorage::CLEAR_IDENTITY : 0);
		return $this;
	}


	/**
	 * Why was user logged out?
	 */
	final public function getLogoutReason(): ?int
	{
		return $this->storage->getLogoutReason();
	}


	/********************* Authorization ****************d*g**/


	/**
	 * Returns a list of effective roles that a user has been granted.
	 */
	public function getRoles(): array
	{
		if (!$this->isLoggedIn()) {
			return [$this->guestRole];
		}

		$identity = $this->getIdentity();
		return $identity && $identity->getRoles() ? $identity->getRoles() : [$this->authenticatedRole];
	}


	/**
	 * Is a user in the specified effective role?
	 */
	final public function isInRole(string $role): bool
	{
		return in_array($role, $this->getRoles(), true);
	}


	/**
	 * Has a user effective access to the Resource?
	 * If $resource is null, then the query applies to all resources.
	 */
	public function isAllowed($resource = IAuthorizator::ALL, $privilege = IAuthorizator::ALL): bool
	{
		foreach ($this->getRoles() as $role) {
			if ($this->getAuthorizator()->isAllowed($role, $resource, $privilege)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Sets authorization handler.
	 * @return static
	 */
	public function setAuthorizator(IAuthorizator $handler)
	{
		$this->authorizator = $handler;
		return $this;
	}


	/**
	 * Returns current authorization handler.
	 */
	final public function getAuthorizator(): ?IAuthorizator
	{
		if (func_num_args()) {
			trigger_error(__METHOD__ . '() parameter $throw is deprecated, use getAuthorizatorIfExists()', E_USER_DEPRECATED);
			$throw = func_get_arg(0);
		}
		if (($throw ?? true) && !$this->authorizator) {
			throw new Nette\InvalidStateException('Authorizator has not been set.');
		}
		return $this->authorizator;
	}


	/**
	 * Returns current authorization handler.
	 */
	final public function getAuthorizatorIfExists(): ?IAuthorizator
	{
		return $this->authorizator;
	}


	/** @deprecated */
	final public function hasAuthorizator(): bool
	{
		return (bool) $this->authorizator;
	}
}
