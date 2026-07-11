<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Passwords::bcrypt() and argon2id() factories.
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


test('bcrypt factory hashes and verifies with given cost', function () {
	$passwords = Passwords::bcrypt(4);
	$hash = $passwords->hash('dg');

	Assert::match('~^\$2y\$04\$.{53}$~', $hash);
	Assert::true($passwords->verify('dg', $hash));
	Assert::false($passwords->needsRehash($hash));
	Assert::true(Passwords::bcrypt(5)->needsRehash($hash));
});


test('argon2id factory hashes and verifies', function () {
	if (!defined('PASSWORD_ARGON2ID')) {
		Tester\Environment::skip('Argon2 is not available.');
	}

	$passwords = Passwords::argon2id(memoryCost: 8, timeCost: 1, threads: 1);
	$hash = $passwords->hash('dg');

	Assert::match('~^\$argon2id\$~', $hash);
	Assert::true($passwords->verify('dg', $hash));
	Assert::false($passwords->needsRehash($hash));
});
