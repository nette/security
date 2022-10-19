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

	private const MIN_LENGTH = 13;

	private Http\IRequest $request;
	private Http\IResponse $response;
	private ?string $uid = null;
	private string $cookieName = 'userid';
	private ?string $cookieDomain = null;
	private string $cookieSameSite = 'Lax';
	private string|int|null $cookieExpiration = null;


	public function __construct(Http\IRequest $request, Http\IResponse $response)
	{
		$this->response = $response;
		$this->request = $request;
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$uid = (string) $identity->getId();
		if (strlen($uid) < self::MIN_LENGTH) {
			throw new \LogicException('UID is too short.');
		}

		$this->uid = $uid;
		$this->response->setCookie(
			$this->cookieName,
			$uid,
			$this->cookieExpiration,
			domain: $this->cookieDomain,
			sameSite: $this->cookieSameSite,
		);
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->uid = '';
		$this->response->deleteCookie(
			$this->cookieName,
			domain: $this->cookieDomain,
		);
	}


	public function getState(): array
	{
		if ($this->uid === null) {
			$uid = $this->request->getCookie($this->cookieName);
			$this->uid = is_string($uid) && strlen($uid) >= self::MIN_LENGTH ? $uid : '';
		}

		return $this->uid
			? [true, new Nette\Security\SimpleIdentity($this->uid), null]
			: [false, null, null];
	}


	public function setExpiration(string|int|null $expire, bool $clearIdentity): void
	{
		$this->cookieExpiration = $expire;
	}


	public function setCookieParameters(
		?string $name = null,
		?string $domain = null,
		?string $sameSite = null,
	) {
		$this->cookieName = $name ?? $this->cookieName;
		$this->cookieDomain = $domain ?? $this->cookieDomain;
		$this->cookieSameSite = $sameSite ?? $this->cookieSameSite;
	}
}
