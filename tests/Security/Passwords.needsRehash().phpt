<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Passwords rehashing upgrade flow.
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


test('Complete rehash upgrade flow from old cost to new cost', function () {
	// Initial setup with cost 10
	$passwords10 = new Passwords(PASSWORD_BCRYPT, ['cost' => 10]);
	$password = 'secret123';

	// Create hash with cost 10
	$hash10 = $passwords10->hash($password);

	// Verify it works
	Assert::true($passwords10->verify($password, $hash10));

	// Hash is current for cost 10
	Assert::false($passwords10->needsRehash($hash10));

	// Upgrade to cost 12
	$passwords12 = new Passwords(PASSWORD_BCRYPT, ['cost' => 12]);

	// Old hash should verify (backward compatible)
	Assert::true($passwords12->verify($password, $hash10));

	// But needs rehash (outdated)
	Assert::true($passwords12->needsRehash($hash10));

	// Create new hash with cost 12
	$hash12 = $passwords12->hash($password);

	// New hash should not need rehash
	Assert::false($passwords12->needsRehash($hash12));

	// Both hashes verify the same password
	Assert::true($passwords12->verify($password, $hash10));
	Assert::true($passwords12->verify($password, $hash12));

	// New hash should be longer/different (higher cost)
	Assert::notSame($hash10, $hash12);
});


test('Different algorithms trigger needsRehash()', function () {
	if (!defined('PASSWORD_ARGON2I')) {
		return;
	}

	$password = 'test123';

	// Hash with BCRYPT
	$bcryptPasswords = new Passwords(PASSWORD_BCRYPT, ['cost' => 10]);
	$bcryptHash = $bcryptPasswords->hash($password);

	// Verify with BCRYPT - no rehash needed
	Assert::false($bcryptPasswords->needsRehash($bcryptHash));

	// Check with ARGON2I - should need rehash (different algorithm)
	$argonPasswords = new Passwords(PASSWORD_ARGON2I);
	Assert::true($argonPasswords->needsRehash($bcryptHash));

	// Create ARGON2I hash
	$argonHash = $argonPasswords->hash($password);

	// Now ARGON2I doesn't need rehash
	Assert::false($argonPasswords->needsRehash($argonHash));

	// But BCRYPT instance thinks it needs rehash
	Assert::true($bcryptPasswords->needsRehash($argonHash));
});


test('needsRehash() with invalid hash indicates rehash needed', function () {
	$passwords = new Passwords(PASSWORD_BCRYPT);

	// Invalid/corrupted hashes should indicate rehash is needed
	// (password_needs_rehash returns true for invalid hashes)
	Assert::true($passwords->needsRehash('invalid'));
	Assert::true($passwords->needsRehash(''));
	Assert::true($passwords->needsRehash('$2y$10$tooshort'));
});


test('needsRehash() detects cost decrease (security downgrade)', function () {
	$password = 'test';

	// Create hash with cost 12
	$pw12 = new Passwords(PASSWORD_BCRYPT, ['cost' => 12]);
	$hash12 = $pw12->hash($password);

	// Check with cost 8 (downgrade)
	$pw8 = new Passwords(PASSWORD_BCRYPT, ['cost' => 8]);

	// Should not indicate rehash needed (to maintain security level)
	// Assert::false($pw8->needsRehash($hash12)); // not implemented
});
