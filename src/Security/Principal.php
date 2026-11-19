<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * The one whose access is decided: the identity of a logged-in user (null for a guest), the effective roles
 * and the voters deciding on them.
 */
final readonly class Principal
{
	public function __construct(
		private ?IIdentity $identity,
		/** @var list<string> */
		private array $roles,
		/** @var list<Voter> */
		private array $voters = [],
		private ?IIdentity $guestIdentity = null,
	) {
	}


	/**
	 * Returns the identity of a logged-in user, null for a guest.
	 */
	public function getIdentity(): ?IIdentity
	{
		return $this->identity;
	}


	/**
	 * Checks whether this is a logged-in user, or an identity given to User::createPrincipal(). False for a guest,
	 * even when the User retains an identity after logout or provides a guest identity.
	 */
	public function isLoggedIn(): bool
	{
		return $this->identity !== null;
	}


	/**
	 * Returns the guest identity provided by the authenticator, null for a logged-in user or when there is none.
	 */
	public function getGuestIdentity(): ?IIdentity
	{
		return $this->identity === null ? $this->guestIdentity : null;
	}


	/**
	 * Checks whether this is the logged-in user with the given ID, so a guest never matches a missing one.
	 */
	public function hasId(string|int|null $id): bool
	{
		return $this->identity !== null && $this->identity->getId() === $id;
	}


	/**
	 * @return list<string>
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}


	public function isInRole(string $role): bool
	{
		return in_array($role, $this->roles, true);
	}


	/**
	 * Checks whether a voter allows access to the given resource (a name, an object or a class name)
	 * and privilege and none forbids it. Null means no particular resource or privilege is asked about;
	 * what that means is up to the voters (for the ACL all resources or all privileges).
	 */
	public function isAllowed(mixed $resource = null, ?string $privilege = null): bool
	{
		if (!$this->voters) {
			throw new Nette\InvalidStateException('No voter has been added. Register a service implementing Nette\Security\Voter, or call User::addVoter().');
		}

		$allowed = false;
		foreach ($this->voters as $voter) {
			$vote = $voter->vote($this, $resource, $privilege);
			if ($vote === Vote::Forbid) {
				return false;
			}

			$allowed = $allowed || $vote === Vote::Allow;
		}

		return $allowed;
	}
}
