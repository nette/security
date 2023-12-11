<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityHttp;

use Nette;
use Nette\Http;
use Nette\Security\IIdentity;
use function is_string, strlen;


/**
 * Cookie storage for Nette\Security\User object.
 */
final class CookieStorage implements Nette\Security\UserStorage
{
	private const MinLength = 13;
	private ?string $uid = null;
	private string $cookieName = 'userid';
	private ?string $cookieDomain = null;
	private string $cookieSameSite = 'Lax';
	private ?string $cookieExpiration = null;


	public function __construct(
		private readonly Http\IRequest $request,
		private readonly Http\IResponse $response,
	) {
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$uid = (string) $identity->getId();
		if (strlen($uid) < self::MinLength) {
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
			$this->uid = is_string($uid) && strlen($uid) >= self::MinLength ? $uid : '';
		}

		return $this->uid
			? [true, new Nette\Security\SimpleIdentity($this->uid), null]
			: [false, null, null];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
		$this->cookieExpiration = $expire;
	}


	/** @param  'Lax'|'Strict'|'None'|null  $sameSite */
	public function setCookieParameters(
		?string $name = null,
		?string $domain = null,
		?string $sameSite = null,
	): void
	{
		$this->cookieName = $name ?? $this->cookieName;
		$this->cookieDomain = $domain ?? $this->cookieDomain;
		$this->cookieSameSite = $sameSite ?? $this->cookieSameSite;
	}
}
