<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;


/**
 * Trivial implementation of Authenticator. Passwords may be stored in plain text
 * or as crypt-format hashes (e.g. from password_hash()); the format is detected automatically.
 */
class SimpleAuthenticator implements Authenticator
{
	public function __construct(
		/** @var array<string, string>  username => password or crypt-format hash */
		#[\SensitiveParameter]
		private readonly array $passwords,
		/** @var array<string, string|list<string>|null> */
		private readonly array $roles = [],
		/** @var array<string, array<string, mixed>> */
		private readonly array $data = [],
	) {
	}


	/**
	 * Authenticates against the in-memory list of users (case-insensitive username).
	 * @throws AuthenticationException
	 */
	public function authenticate(
		string $username,
		#[\SensitiveParameter]
		string $password,
	): IIdentity
	{
		foreach ($this->passwords as $name => $pass) {
			if (strcasecmp($name, $username) === 0) {
				if ($this->verifyPassword($password, $pass)) {
					return new SimpleIdentity($name, $this->roles[$name] ?? null, $this->data[$name] ?? []);
				} else {
					throw new AuthenticationException('Invalid password.', self::InvalidCredential);
				}
			}
		}

		throw new AuthenticationException("User '$username' not found.", self::IdentityNotFound);
	}


	protected function verifyPassword(string $password, string $passOrHash): bool
	{
		// the crypt-format '$ident$' prefix + length marks a hash; unknown algorithms fail closed in password_verify()
		return preg_match('~^\$[^$]+\$.{20,}~', $passOrHash)
			? password_verify($password, $passOrHash)
			: hash_equals($passOrHash, $password);
	}
}
