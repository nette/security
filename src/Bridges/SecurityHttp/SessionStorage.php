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


/**
 * Session storage for Nette\Security\User object.
 */
final class SessionStorage implements Nette\Security\UserStorage
{
	use Nette\SmartObject;

	/** @var string */
	private $namespace = '';

	/** @var Session */
	private $sessionHandler;

	/** @var SessionSection */
	private $sessionSection;


	public function __construct(Session $sessionHandler)
	{
		$this->sessionHandler = $sessionHandler;
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$section = $this->getSessionSection(true);
		$section->authenticated = true;
		$section->reason = null;
		$section->authTime = time(); // informative value
		$section->identity = $identity;

		// Session Fixation defence
		$this->sessionHandler->regenerateId();
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$section = $this->getSessionSection(true);
		$section->authenticated = false;
		$section->reason = self::LOGOUT_MANUAL;
		$section->authTime = null;

		// Session Fixation defence
		$this->sessionHandler->regenerateId();
	}


	public function getState(): array
	{
		$session = $this->getSessionSection(false);
		return $session
			? [(bool) $session->authenticated, $session->identity, $session->reason]
			: [false, null, null];
	}


	public function setExpiration(?string $time, bool $clearIdentity = false): void
	{
		$section = $this->getSessionSection(true);
		if ($time) {
			$time = Nette\Utils\DateTime::from($time)->format('U');
			$section->expireTime = $time;
			$section->expireDelta = $time - time();

		} else {
			unset($section->expireTime, $section->expireDelta);
		}

		$section->expireIdentity = (bool) $clearIdentity;
		$section->setExpiration($time, 'foo'); // time check
	}


	/**
	 * Changes namespace; allows more users to share a session.
	 * @return static
	 */
	public function setNamespace(string $namespace)
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
	protected function getSessionSection(bool $need): ?SessionSection
	{
		if ($this->sessionSection !== null) {
			return $this->sessionSection;
		}

		if (!$need && !$this->sessionHandler->exists()) {
			return null;
		}

		$this->sessionSection = $section = $this->sessionHandler->getSection('Nette.Http.UserStorage/' . $this->namespace);

		if (!$section->identity instanceof IIdentity || !is_bool($section->authenticated)) {
			$section->remove();
		}

		if ($section->authenticated && $section->expireDelta > 0) { // check time expiration
			if ($section->expireTime < time()) {
				$section->reason = self::LOGOUT_INACTIVITY;
				$section->authenticated = false;
				if ($section->expireIdentity) {
					unset($section->identity);
				}
			}
			$section->expireTime = time() + $section->expireDelta; // sliding expiration
		}

		if (!$section->authenticated) {
			unset($section->expireTime, $section->expireDelta, $section->expireIdentity, $section->authTime);
		}

		return $this->sessionSection;
	}
}
