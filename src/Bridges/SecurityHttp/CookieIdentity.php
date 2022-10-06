<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityHttp;

use Nette;
use Nette\Security\IIdentity;


/**
 * Identity used by CookieStorage
 */
final class CookieIdentity implements IIdentity
{
	use Nette\SmartObject;

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


	public function getRoles(): array
	{
		throw new Nette\NotSupportedException;
	}


	public function getData(): array
	{
		throw new Nette\NotSupportedException;
	}
}
