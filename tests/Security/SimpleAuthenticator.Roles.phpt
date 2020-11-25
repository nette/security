<?php

/**
 * Test: Nette\Security\SimpleAuthenticator and roles
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
$usersRoles = [
	'admin' => ['admin', 'user'],
	'user' => 'user',
];
$expectedRoles = [
	'admin' => ['admin', 'user'],
	'user' => ['user'],
	'john' => [],
];

$authenticator = new SimpleAuthenticator($users, $usersRoles);

foreach ($users as $username => $password) {
	$identity = $authenticator->authenticate($username, $password);
	Assert::equal($username, $identity->getId());
	Assert::equal($expectedRoles[$username], $identity->getRoles());
}
