<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;
use Nette\Utils\Arrays;


/**
 * User authentication and authorization.
 *
 * @property-read bool $loggedIn
 * @property-read IIdentity $identity
 * @property-read mixed $id
 * @property-read array $roles
 * @property-read int $logoutReason
 * @property   IAuthenticator $authenticator
 * @property   Authorizator $authorizator
 */
class User
{
	use Nette\SmartObject;

	/** @deprecated */
	public const
		MANUAL = IUserStorage::MANUAL,
		INACTIVITY = IUserStorage::INACTIVITY;

	/** Log-out reason */
	public const
		LOGOUT_MANUAL = UserStorage::LOGOUT_MANUAL,
		LOGOUT_INACTIVITY = UserStorage::LOGOUT_INACTIVITY;

	/** @var string  default role for unauthenticated user */
	public $guestRole = 'guest';

	/** @var string  default role for authenticated user without own identity */
	public $authenticatedRole = 'authenticated';

	/** @var callable[]  function (User $sender): void; Occurs when the user is successfully logged in */
	public $onLoggedIn = [];

	/** @var callable[]  function (User $sender): void; Occurs when the user is logged out */
	public $onLoggedOut = [];

	/** @var UserStorage|IUserStorage  Session storage for current user */
	private $storage;

	/** @var IAuthenticator|null */
	private $authenticator;

	/** @var Authorizator|null */
	private $authorizator;

	/** @var IIdentity|null */
	private $identity;

	/** @var bool|null */
	private $authenticated;

	/** @var int|null */
	private $logoutReason;


	public function __construct(
		?IUserStorage $legacyStorage = null,
		?IAuthenticator $authenticator = null,
		?Authorizator $authorizator = null,
		?UserStorage $storage = null
	) {
		$this->storage = $storage ?? $legacyStorage; // back compatibility
		if (!$this->storage) {
			throw new Nette\InvalidStateException('UserStorage has not been set.');
		}

		$this->authenticator = $authenticator;
		$this->authorizator = $authorizator;
	}


	/**
	 * @return UserStorage|IUserStorage
	 */
	final public function getStorage()
	{
		return $this->storage;
	}


	/********************* Authentication ****************d*g**/


	/**
	 * Conducts the authentication process. Parameters are optional.
	 * @param  string|IIdentity  $user  name or Identity
	 * @throws AuthenticationException if authentication was not successful
	 */
	public function login(
		$user,
		#[\SensitiveParameter]
		?string $password = null
	): void
	{
		$this->logout(true);
		if ($user instanceof IIdentity) {
			$this->identity = $user;
		} else {
			$authenticator = $this->getAuthenticator();
			$this->identity = $authenticator instanceof Authenticator
				? $authenticator->authenticate(...func_get_args())
				: $authenticator->authenticate(func_get_args());
		}

		$id = $this->authenticator instanceof IdentityHandler
			? $this->authenticator->sleepIdentity($this->identity)
			: $this->identity;
		if ($this->storage instanceof UserStorage) {
			$this->storage->saveAuthentication($id);
		} else {
			$this->storage->setIdentity($id);
			$this->storage->setAuthenticated(true);
		}

		$this->authenticated = true;
		$this->logoutReason = null;
		Arrays::invoke($this->onLoggedIn, $this);
	}


	/**
	 * Logs out the user from the current session.
	 */
	final public function logout(bool $clearIdentity = false): void
	{
		$logged = $this->isLoggedIn();

		if ($this->storage instanceof UserStorage) {
			$this->storage->clearAuthentication($clearIdentity);
		} else {
			$this->storage->setAuthenticated(false);
			if ($clearIdentity) {
				$this->storage->setIdentity(null);
			}
		}

		$this->authenticated = false;
		$this->logoutReason = self::MANUAL;
		if ($logged) {
			Arrays::invoke($this->onLoggedOut, $this);
		}

		$this->identity = $clearIdentity ? null : $this->identity;
	}


	/**
	 * Is this user authenticated?
	 */
	final public function isLoggedIn(): bool
	{
		if ($this->authenticated === null) {
			$this->getStoredData();
		}

		return $this->authenticated;
	}


	/**
	 * Returns current user identity, if any.
	 */
	final public function getIdentity(): ?IIdentity
	{
		if ($this->authenticated === null) {
			$this->getStoredData();
		}

		return $this->identity;
	}


	private function getStoredData(): void
	{
		if ($this->storage instanceof UserStorage) {
			(function (bool $state, ?IIdentity $id, ?int $reason) use (&$identity) {
				$identity = $id;
				$this->authenticated = $state;
				$this->logoutReason = $reason;
			})(...$this->storage->getState());
		} else {
			$identity = $this->storage->getIdentity();
			$this->authenticated = $this->storage->isAuthenticated();
			$this->logoutReason = $this->storage->getLogoutReason();
		}

		$this->identity = $identity && $this->authenticator instanceof IdentityHandler
			? $this->authenticator->wakeupIdentity($identity)
			: $identity;
		$this->authenticated = $this->authenticated && $this->identity;
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


	final public function refreshStorage(): void
	{
		$this->identity = $this->authenticated = $this->logoutReason = null;
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
	 * Enables log out after inactivity (like '20 minutes').
	 * @param  string|null  $expire
	 * @param  int|bool  $clearIdentity
	 * @return static
	 */
	public function setExpiration($expire, $clearIdentity = null)
	{
		if ($expire !== null && !is_string($expire)) {
			trigger_error("Expiration should be a string like '20 minutes' etc.", E_USER_DEPRECATED);
		}

		if (func_num_args() > 2) {
			$clearIdentity = $clearIdentity || func_get_arg(2);
			trigger_error(__METHOD__ . '() third parameter is deprecated, use second one: setExpiration($time, true|false)', E_USER_DEPRECATED);
		}

		$arg = $this->storage instanceof UserStorage
			? (bool) $clearIdentity
			: ($clearIdentity ? IUserStorage::CLEAR_IDENTITY : 0);
		$this->storage->setExpiration($expire, $arg);
		return $this;
	}


	/**
	 * Why was user logged out? Returns LOGOUT_MANUAL or LOGOUT_INACTIVITY.
	 */
	final public function getLogoutReason(): ?int
	{
		return $this->logoutReason;
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
		foreach ($this->getRoles() as $r) {
			if ($role === ($r instanceof Role ? $r->getRoleId() : $r)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Has a user effective access to the Resource?
	 * If $resource is null, then the query applies to all resources.
	 */
	public function isAllowed($resource = Authorizator::ALL, $privilege = Authorizator::ALL): bool
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
	public function setAuthorizator(Authorizator $handler)
	{
		$this->authorizator = $handler;
		return $this;
	}


	/**
	 * Returns current authorization handler.
	 */
	final public function getAuthorizator(): ?Authorizator
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
	final public function getAuthorizatorIfExists(): ?Authorizator
	{
		return $this->authorizator;
	}


	/** @deprecated */
	final public function hasAuthorizator(): bool
	{
		return (bool) $this->authorizator;
	}
}
