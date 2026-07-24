<?php declare(strict_types=1);

/**
 * Test: Nette\Security\SimpleAuthenticator
 */

use Nette\Security\SimpleAuthenticator;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$users = [
	'john' => 'password123!',
	'admin' => 'admin',
];

$authenticator = new SimpleAuthenticator($users);

$identity = $authenticator->authenticate('john', 'password123!');
Assert::type(Nette\Security\IIdentity::class, $identity);
Assert::equal('john', $identity->getId());

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


// hashed passwords are detected automatically and may be mixed with plain ones
$hash = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4]);
$authenticator = new SimpleAuthenticator([
	'john' => $hash,
	'mary' => 'plain',
	'jane' => '$uperSecret', // plain text; a single '$' is not the crypt '$ident$' prefix
	'jim' => '$my$password', // plain text; too short after '$my$' to be a hash
	'joe' => crypt('secret', '$6$rounds=1000$abcdefgh$'), // legacy sha512-crypt
]);

Assert::equal('john', $authenticator->authenticate('john', 'secret')->getId());
Assert::equal('mary', $authenticator->authenticate('mary', 'plain')->getId());
Assert::equal('jane', $authenticator->authenticate('jane', '$uperSecret')->getId());
Assert::equal('jim', $authenticator->authenticate('jim', '$my$password')->getId());
Assert::equal('joe', $authenticator->authenticate('joe', 'secret')->getId());

Assert::exception(
	fn() => $authenticator->authenticate('john', $hash), // the hash itself is not the password
	Nette\Security\AuthenticationException::class,
	'Invalid password.',
);


// a hash with an unknown algorithm fails closed: neither the password nor the hash itself works
$unknownHash = '$scrypt$n=16384,r=8,p=1$c2FsdHNhbHQ$K5d0Y2x5c2FsdA';
$authenticator = new SimpleAuthenticator(['john' => $unknownHash]);

Assert::exception(
	fn() => $authenticator->authenticate('john', 'secret'),
	Nette\Security\AuthenticationException::class,
	'Invalid password.',
);

Assert::exception(
	fn() => $authenticator->authenticate('john', $unknownHash),
	Nette\Security\AuthenticationException::class,
	'Invalid password.',
);
