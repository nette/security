<?php

/**
 * Test: Nette\Security\SimpleAuthenticator
 */

declare(strict_types=1);

use Nette\Security\Passwords;
use Nette\Security\SimpleAuthenticator;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$users = [
	'john' => '$2a$12$dliX6LynG/iChDUF7DhKzulN7d3nU.l3/RozE1MmEaxxBWdZXppm2',
	'admin' => 'admin',
];

$authenticator = new SimpleAuthenticator($users);

$identity = $authenticator->authenticate('admin', 'admin');
Assert::type(Nette\Security\IIdentity::class, $identity);
Assert::equal('admin', $identity->getId());

Assert::exception(
	fn() => $authenticator->authenticate('admin', 'wrong password'),
	Nette\Security\AuthenticationException::class,
	'Invalid password.',
);

Assert::exception(
	fn() => $authenticator->authenticate('nobody', 'password'),
	Nette\Security\AuthenticationException::class,
	"User 'nobody' not found.",
);


$authenticator = new SimpleAuthenticator($users, verifier: new Passwords);

$identity = $authenticator->authenticate('john', 'password123!');
Assert::type(Nette\Security\IIdentity::class, $identity);
Assert::equal('john', $identity->getId());

Assert::exception(
	fn() => $authenticator->authenticate('john', $users['john']),
	Nette\Security\AuthenticationException::class,
	'Invalid password.',
);
