<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityHttp;

use Nette;
use Nette\Http\Session;
use Nette\Http\SessionSection;
use Nette\Security\IIdentity;
use Nette\Security\User;


/**
 * Session storage for Nette\Security\User object.
 */
final class SessionStorage implements Nette\Security\UserStorage
{
	private string $namespace = '';
	private Session $sessionHandler;
	private ?SessionSection $sessionSection = null;
	private ?int $expireTime = null;
	private bool $expireIdentity = false;


	public function __construct(Session $sessionHandler)
	{
		$this->sessionHandler = $sessionHandler;
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$section = $this->getSessionSection();
		$section->set('authenticated', true);
		$section->set('reason', null);
		$section->set('authTime', time()); // informative value
		$section->set('identity', $identity);
		$this->setupExpiration();

		// Session Fixation defence
		$this->sessionHandler->regenerateId();
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$section = $this->getSessionSection();
		$section->set('authenticated', false);
		$section->set('reason', User::LogoutManual);
		$section->set('authTime', null);
		if ($clearIdentity === true) {
			$section->set('identity', null);
		}

		// Session Fixation defence
		$this->sessionHandler->regenerateId();
	}


	public function getState(): array
	{
		$section = $this->getSessionSection();
		return $section
			? [(bool) $section->get('authenticated'), $section->get('identity'), $section->get('reason')]
			: [false, null, null];
	}


	public function setExpiration(?string $time, bool $clearIdentity = false): void
	{
		$this->expireTime = $time ? (int) Nette\Utils\DateTime::from($time)->format('U') : null;
		$this->expireIdentity = $clearIdentity;

		if ($this->sessionSection && $this->sessionSection->get('authenticated')) {
			$this->setupExpiration();
		}
	}


	private function setupExpiration(): void
	{
		$section = $this->sessionSection;
		if ($this->expireTime) {
			$section->set('expireTime', $this->expireTime);
			$section->set('expireDelta', $this->expireTime - time());
		} else {
			$section->remove(['expireTime', 'expireDelta']);
		}

		$section->set('expireIdentity', $this->expireIdentity);
		$section->setExpiration((string) $this->expireTime, 'foo'); // time check
	}


	/**
	 * Changes namespace; allows more users to share a session.
	 */
	public function setNamespace(string $namespace): static
	{
		if ($this->namespace !== $namespace) {
			$this->namespace = $namespace;
			$this->sessionSection = null;
		}

		return $this;
	}


	/**
	 * Returns current namespace.
	 */
	public function getNamespace(): string
	{
		return $this->namespace;
	}


	/**
	 * Returns and initializes $this->sessionSection.
	 */
	protected function getSessionSection(): ?SessionSection
	{
		if ($this->sessionSection !== null) {
			return $this->sessionSection;
		}

		$this->sessionSection = $section = $this->sessionHandler->getSection('Nette.Http.UserStorage/' . $this->namespace);

		if (!$section->get('identity') instanceof IIdentity || !is_bool($section->get('authenticated'))) {
			$section->remove();
		}

		if ($section->get('authenticated') && $section->get('expireDelta') > 0) { // check time expiration
			if ($section->get('expireTime') < time()) {
				$section->set('reason', User::LogoutInactivity);
				$section->set('authenticated', false);
				if ($section->get('expireIdentity')) {
					$section->remove('identity');
				}
			}

			$section->set('expireTime', time() + $section->expireDelta); // sliding expiration
		}

		if (!$section->get('authenticated')) {
			$section->remove(['expireTime', 'expireDelta', 'expireIdentity', 'authTime']);
		}

		return $this->sessionSection;
	}
}
