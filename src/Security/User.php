<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;
use Nette\Utils\Arrays;
use function func_get_args, is_string, sprintf;


/**
 * User authentication and authorization.
 *
 * @property-read bool $loggedIn
 * @property-read ?IIdentity $identity
 * @property-deprecated string|int|null $id
 * @property-deprecated list<string> $roles
 * @property-deprecated ?int $logoutReason
 * @property-deprecated Authenticator $authenticator
 * @property-deprecated Authorizator $authorizator
 */
class User
{
	use Nette\SmartObject;

	/** Log-out reason */
	public const
		LogoutManual = 1,
		LogoutInactivity = 2;

	#[\Deprecated('use User::LogoutManual')]
	public const LOGOUT_MANUAL = self::LogoutManual;

	#[\Deprecated('use User::LogoutManual')]
	public const MANUAL = self::LogoutManual;

	#[\Deprecated('use User::LogoutInactivity')]
	public const LOGOUT_INACTIVITY = self::LogoutInactivity;

	#[\Deprecated('use User::LogoutInactivity')]
	public const INACTIVITY = self::LogoutInactivity;

	/** role for an unauthenticated user, unless a guest identity provides its own roles */
	public string $guestRole = 'guest';

	/** default role for authenticated user without own identity */
	public string $authenticatedRole = 'authenticated';

	/** keep identity available (via getIdentity() and getId()) after logout or expiration; depends on the storage implementation */
	public bool $persistIdentity = true;

	/** @var array<callable(static): void>  Occurs when the user is successfully logged in */
	public array $onLoggedIn = [];

	/** @var array<callable(static): void>  Occurs when the user is logged out */
	public array $onLoggedOut = [];

	private ?IIdentity $identity = null;
	private ?bool $authenticated = null;
	private ?int $logoutReason = null;
	private ?IIdentity $guestIdentity = null;
	private bool $guestIdentityResolved = false;

	/** @var list<Voter> */
	private array $voters;
	private ?Authorizator $authorizator = null;
	private ?Voter $authorizatorVoter = null;


	public function __construct(
		private readonly UserStorage $storage,
		private ?Authenticator $authenticator = null,
		Voter ...$voters,
	) {
		$this->voters = array_values($voters);
	}


	final public function getStorage(): UserStorage
	{
		return $this->storage;
	}


	/********************* Authentication ****************d*g**/


	/**
	 * Authenticates the user. Accepts username and password, or an IIdentity directly.
	 * @param  string|IIdentity  $username  username or identity
	 * @throws AuthenticationException if authentication was not successful
	 */
	public function login(
		string|IIdentity $username,
		#[\SensitiveParameter]
		?string $password = null,
	): void
	{
		$this->logout(clearIdentity: true);
		if ($username instanceof IIdentity) {
			$this->identity = $username;
		} else {
			$authenticator = $this->getAuthenticator();
			$this->identity = $authenticator->authenticate(...func_get_args());
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
	 * Logs out the user from the current session. The identity is kept available afterwards,
	 * unless $clearIdentity is set or the $persistIdentity property is disabled.
	 */
	final public function logout(bool $clearIdentity = false): void
	{
		$clearIdentity = $clearIdentity || !$this->persistIdentity;
		$logged = $this->isLoggedIn();
		// the last condition covers a stored authentication vetoed by wakeupIdentity(); otherwise there is nothing to change
		if ($logged || $clearIdentity || $this->storage->getState()[0]) {
			$this->storage->clearAuthentication($clearIdentity);
			$this->logoutReason = self::LogoutManual;
		}

		$this->authenticated = false;
		if ($logged) {
			Arrays::invoke($this->onLoggedOut, $this);
		}

		$this->identity = $clearIdentity ? null : $this->identity;
	}


	/**
	 * Checks whether the user is authenticated.
	 */
	final public function isLoggedIn(): bool
	{
		$this->loadStoredData();
		return (bool) $this->authenticated;
	}


	/**
	 * Returns the user identity. When not logged in, this is the retained identity (unless $persistIdentity
	 * is disabled) or a guest identity if the authenticator provides one; null otherwise.
	 */
	final public function getIdentity(): ?IIdentity
	{
		$this->loadStoredData();
		return $this->identity ?? $this->resolveGuestIdentity();
	}


	private function loadStoredData(): void
	{
		if ($this->authenticated !== null) {
			return;
		}

		[$this->authenticated, $identity, $this->logoutReason] = $this->storage->getState();

		$identity = $identity && $this->authenticator instanceof IdentityHandler
			? $this->authenticator->wakeupIdentity($identity)
			: $identity;
		$this->authenticated = $this->authenticated && $identity !== null;
		$this->identity = !$this->authenticated && !$this->persistIdentity ? null : $identity;
	}


	/** Returns the guest identity provided by the IdentityHandler authenticator, or null. */
	private function resolveGuestIdentity(): ?IIdentity
	{
		if (!$this->guestIdentityResolved) {
			$this->guestIdentityResolved = true;
			$this->guestIdentity = $this->authenticator instanceof IdentityHandler
				? $this->authenticator->getGuestIdentity()
				: null;
		}

		return $this->guestIdentity;
	}


	/**
	 * Returns the ID of the identity returned by getIdentity(), so it may be the retained or guest
	 * identity's ID even when not logged in; null if there is no identity.
	 */
	public function getId(): string|int|null
	{
		$identity = $this->getIdentity();
		return $identity?->getId();
	}


	/**
	 * Discards the cached authentication state and identity, forcing a reload on next access.
	 */
	final public function refreshStorage(): void
	{
		$this->identity = $this->authenticated = $this->logoutReason = null;
		$this->guestIdentity = null;
		$this->guestIdentityResolved = false;
	}


	/**
	 * Sets authentication handler.
	 */
	public function setAuthenticator(Authenticator $handler): static
	{
		$this->authenticator = $handler;
		$this->guestIdentityResolved = false;
		return $this;
	}


	/**
	 * Returns authentication handler.
	 */
	final public function getAuthenticator(): Authenticator
	{
		if (!$this->authenticator) {
			throw new Nette\InvalidStateException('Authenticator has not been set.');
		}

		return $this->authenticator;
	}


	/**
	 * Returns authentication handler, or null if none is set.
	 */
	final public function getAuthenticatorIfExists(): ?Authenticator
	{
		return $this->authenticator;
	}


	/** @deprecated */
	final public function hasAuthenticator(): bool
	{
		return (bool) $this->authenticator;
	}


	/**
	 * Enables log out after inactivity (like '20 minutes'). The identity is kept available afterwards,
	 * unless $clearIdentity is set or the $persistIdentity property is disabled.
	 */
	public function setExpiration(?string $expire, bool $clearIdentity = false): static
	{
		$this->storage->setExpiration($expire, $clearIdentity || !$this->persistIdentity);
		return $this;
	}


	/**
	 * Returns the logout reason: LogoutManual or LogoutInactivity, or null if not applicable.
	 */
	final public function getLogoutReason(): ?int
	{
		return $this->logoutReason;
	}


	/********************* Authorization ****************d*g**/


	/**
	 * Returns effective roles derived from the login state, not from the (possibly retained) identity.
	 * Logged in: the identity's roles, or authenticatedRole. Otherwise: the guest identity's roles, or guestRole.
	 * @return list<string>
	 */
	public function getRoles(): array
	{
		if (!$this->isLoggedIn()) {
			return $this->getGuestRoles();
		}

		$identity = $this->getIdentity();
		return $identity ? $this->getIdentityRoles($identity) : [$this->authenticatedRole];
	}


	/**
	 * Checks whether the user has the specified effective role.
	 */
	final public function isInRole(string $role): bool
	{
		return $this->getPrincipal()->isInRole($role);
	}


	/**
	 * Checks whether a voter allows the user access to the given resource (a name, an object or a class name)
	 * and privilege and none forbids it. Null means all resources or all privileges.
	 */
	public function isAllowed(mixed $resource = Authorizator::All, ?string $privilege = Authorizator::All): bool
	{
		return $this->getPrincipal()->isAllowed($resource, $privilege);
	}


	/**
	 * Returns the user as the voters see them: the identity only while logged in, and the effective roles.
	 */
	public function getPrincipal(): Principal
	{
		return $this->createPrincipal($this->isLoggedIn() ? $this->getIdentity() : null);
	}


	/**
	 * Returns the principal of the given identity as if it were logged in, or of a guest for null, to decide about
	 * someone else than the current user. The identity is taken as it is; nothing is called or stored.
	 */
	final public function createPrincipal(?IIdentity $identity): Principal
	{
		$roles = $identity ? $this->getIdentityRoles($identity) : $this->getGuestRoles();
		return new Principal($identity, $roles, $this->getVoters());
	}


	/** @return list<string> */
	private function getGuestRoles(): array
	{
		$identity = $this->resolveGuestIdentity();
		return $identity ? $this->getIdentityRoles($identity) : [$this->guestRole];
	}


	/**
	 * Returns the roles of the identity, which must be names.
	 * @return list<string>
	 */
	private function getIdentityRoles(IIdentity $identity): array
	{
		$roles = $identity->getRoles();
		foreach ($roles as $role) {
			if (!is_string($role)) {
				throw new Nette\InvalidStateException(sprintf(
					'Roles of %s must be names, %s given. Role objects are no longer supported.',
					$identity::class,
					get_debug_type($role),
				));
			}
		}

		return $roles;
	}


	/** @return list<Voter> */
	private function getVoters(): array
	{
		return $this->authorizatorVoter ? [...$this->voters, $this->authorizatorVoter] : $this->voters;
	}


	/**
	 * Adds a voter deciding on authorization.
	 */
	public function addVoter(Voter $voter): static
	{
		$this->voters[] = $voter;
		return $this;
	}


	/**
	 * Sets the role-based authorization handler, asked for each effective role.
	 */
	#[\Deprecated('use User::addVoter()')]
	public function setAuthorizator(Authorizator $handler): static
	{
		$this->authorizator = $handler;
		$this->authorizatorVoter = new readonly class ($handler) implements Voter {
			public function __construct(
				private Authorizator $authorizator,
			) {
			}


			public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
			{
				foreach ($principal->getRoles() as $role) {
					if ($this->authorizator->isAllowed($role, $resource, $privilege)) {
						return Vote::Allow;
					}
				}

				return Vote::Abstain;
			}
		};
		return $this;
	}


	/**
	 * Returns the role-based authorization handler.
	 */
	#[\Deprecated]
	final public function getAuthorizator(): Authorizator
	{
		if (!$this->authorizator) {
			throw new Nette\InvalidStateException('Authorizator has not been set.');
		}

		return $this->authorizator;
	}


	/**
	 * Returns the role-based authorization handler, or null if none is set.
	 */
	#[\Deprecated]
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
