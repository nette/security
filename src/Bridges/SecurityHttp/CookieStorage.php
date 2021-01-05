<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityHttp;

use Nette;
use Nette\Http;
use Nette\Security\IIdentity;


/**
 * Cookie storage for Nette\Security\User object.
 */
final class CookieStorage implements Nette\Security\UserStorage
{
	use Nette\SmartObject;

	/** @var Http\IRequest */
	private $request;

	/** @var Http\IResponse */
	private $response;

	/** @var string */
	private $cookieName = 'userid';

	/** @var ?string */
	private $cookieDomain;

	/** @var string */
	private $cookieSameSite = 'Lax';

	/** @var ?string */
	private $cookieExpiration;


	public function __construct(Http\IRequest $request, Http\IResponse $response)
	{
		$this->response = $response;
		$this->request = $request;
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$this->response->setCookie(
			$this->cookieName,
			$identity->getId(),
			$this->cookieExpiration,
			null,
			$this->cookieDomain
		);
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->response->deleteCookie(
			$this->cookieName,
			null,
			$this->cookieDomain
		);
	}


	public function getState(): array
	{
		$uid = $this->request->getCookie($this->cookieName);
		$identity = is_string($uid)
			? new Nette\Security\SimpleIdentity($uid)
			: null;
		return [(bool) $identity, $identity, null];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
		$this->cookieExpiration = $expire;
	}


	public function setCookieParameters(
		string $name = null,
		string $domain = null,
		string $sameSite = null
	) {
		$this->cookieName = $name ?? $this->cookieName;
		$this->cookieDomain = $domain ?? $this->cookieDomain;
		$this->cookieSameSite = $sameSite ?? $this->cookieSameSite;
	}
}
