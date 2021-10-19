<?php

/**
 * Test: Nette\Security\SimpleAuthenticator and data
 */

declare(strict_types=1);

use Nette\Security\SimpleAuthenticator;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$users = [
	'john' => 'john123',
	'admin' => 'admin123',
	'user' => 'user123',
];
$usersData = [
	'admin' => ['nick' => 'admin', 'email' => 'foo@bar.com'],
	'user' => ['nick' => 'user', 'email' => 'foo@bar.com'],
];
$expectedData = [
	'admin' => ['nick' => 'admin', 'email' => 'foo@bar.com'],
	'user' => ['nick' => 'user', 'email' => 'foo@bar.com'],
	'john' => [],
];

$authenticator = new SimpleAuthenticator($users, [], $usersData);

foreach ($users as $username => $password) {
	$identity = $authenticator->authenticate($username, $password);
	Assert::equal($username, $identity->getId());
	Assert::equal($expectedData[$username], $identity->getData());
}
