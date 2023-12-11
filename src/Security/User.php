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
 * @property-read string|int $id
 * @property-read array $roles
 * @property-read int $logoutReason
 * @property   IAuthenticator $authenticator
 * @property   Authorizator $authorizator
 */
class User
{
	use Nette\SmartObject;

	/** Log-out reason */
	public const
		LogoutManual = 1,
		LogoutInactivity = 2;

	/** @deprecated */
	public const
		MANUAL = self::LogoutManual,
		INACTIVITY = self::LogoutInactivity;

	public const LOGOUT_MANUAL = self::LogoutManual;
	public const LOGOUT_INACTIVITY = self::LogoutInactivity;

	/** default role for unauthenticated user */
	public string $guestRole = 'guest';

	/** default role for authenticated user without own identity */
	public string $authenticatedRole = 'authenticated';

	/** @var callable[]  function (User $sender): void; Occurs when the user is successfully logged in */
	public array $onLoggedIn = [];

	/** @var callable[]  function (User $sender): void; Occurs when the user is logged out */
	public array $onLoggedOut = [];

	private ?IIdentity $identity = null;
	private ?bool $authenticated = null;
	private ?int $logoutReason = null;


	public function __construct(
		private UserStorage $storage,
		private ?IAuthenticator $authenticator = null,
		private ?Authorizator $authorizator = null,
	) {
	}


	final public function getStorage(): UserStorage
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
		string|IIdentity $user,
		#[\SensitiveParameter]
		?string $password = null,
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

		$this->storage->saveAuthentication($id);
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
		$this->storage->clearAuthentication($clearIdentity);
		$this->authenticated = false;
		$this->logoutReason = self::LogoutManual;
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
		(function (bool $state, ?IIdentity $id, ?int $reason) use (&$identity) {
			$identity = $id;
			$this->authenticated = $state;
			$this->logoutReason = $reason;
		})(...$this->storage->getState());

		$this->identity = $identity && $this->authenticator instanceof IdentityHandler
			? $this->authenticator->wakeupIdentity($identity)
			: $identity;
		$this->authenticated = $this->authenticated && $this->identity;
	}


	/**
	 * Returns current user ID, if any.
	 */
	public function getId(): string|int|null
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
	 */
	public function setAuthenticator(IAuthenticator $handler): static
	{
		$this->authenticator = $handler;
		return $this;
	}


	/**
	 * Returns authentication handler.
	 */
	final public function getAuthenticator(): IAuthenticator
	{
		if (!$this->authenticator) {
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
	 */
	public function setExpiration(?string $expire, bool $clearIdentity = false)
	{
		$this->storage->setExpiration($expire, $clearIdentity);
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
	public function isAllowed($resource = Authorizator::All, $privilege = Authorizator::All): bool
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
	 */
	public function setAuthorizator(Authorizator $handler): static
	{
		$this->authorizator = $handler;
		return $this;
	}


	/**
	 * Returns current authorization handler.
	 */
	final public function getAuthorizator(): Authorizator
	{
		if (!$this->authorizator) {
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
