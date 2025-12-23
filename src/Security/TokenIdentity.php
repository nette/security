<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Identity carrying only a token from the client, to be exchanged for the real identity by IdentityHandler::wakeupIdentity().
 */
final readonly class TokenIdentity implements IIdentity
{
	public function __construct(
		private string $token,
	) {
	}


	public function getId(): string
	{
		return $this->token;
	}


	/** @throws Nette\NotSupportedException */
	public function getRoles(): array
	{
		throw new Nette\NotSupportedException('TokenIdentity carries only a token, it has no roles.');
	}


	/**
	 * @return array<string, mixed>
	 * @throws Nette\NotSupportedException
	 */
	public function getData(): array
	{
		throw new Nette\NotSupportedException('TokenIdentity carries only a token, it has no data.');
	}
}
