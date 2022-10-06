<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityHttp;

use Nette;
use Nette\Security\IIdentity;
use function strlen;


/**
 * Identity used by CookieStorage
 */
final readonly class CookieIdentity implements IIdentity
{
	private const MIN_LENGTH = 13;

	private string $uid;


	public function __construct(string $uid)
	{
		if (strlen($uid) < self::MIN_LENGTH) {
			throw new \LogicException('UID is too short.');
		}
		$this->uid = $uid;
	}


	public function getId(): string
	{
		return $this->uid;
	}


	/**
	 * @throws Nette\NotSupportedException
	 */
	public function getRoles(): array
	{
		throw new Nette\NotSupportedException;
	}


	/**
	 * @return array<string, mixed>
	 * @throws Nette\NotSupportedException
	 */
	public function getData(): array
	{
		throw new Nette\NotSupportedException;
	}
}
