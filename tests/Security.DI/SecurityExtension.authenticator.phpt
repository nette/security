<?php

/**
 * Test: SecurityExtension
 */

declare(strict_types=1);

use Nette\Bridges\HttpDI\HttpExtension;
use Nette\Bridges\HttpDI\SessionExtension;
use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$compiler = new DI\Compiler;
$compiler->addExtension('foo', new HttpExtension);
$compiler->addExtension('bar', new SessionExtension);
$compiler->addExtension('security', new SecurityExtension);

$loader = new Nette\DI\Config\Loader;
$config = $loader->load(Tester\FileMock::create('
security:
	users:
		john: john123
		admin: {password: admin123, roles: [admin, user]}
		user: {password: user123}
		moderator: {password: moderator123, roles: moderator}
', 'neon'));

eval($compiler->addConfig($config)->compile());
$container = new Container;

$authenticator = $container->getService('security.authenticator');
Assert::type(Nette\Security\SimpleAuthenticator::class, $authenticator);
Assert::same($authenticator, $container->getService('nette.authenticator'));

$userList = [
	'john' => 'john123',
	'admin' => 'admin123',
	'user' => 'user123',
	'moderator' => 'moderator123',
];
$expectedRoles = [
	'john' => [],
	'admin' => ['admin', 'user'],
	'user' => [],
	'moderator' => ['moderator'],
];

foreach ($userList as $username => $password) {
	$identity = $authenticator->authenticate($username, $password);
	Assert::equal($username, $identity->getId());
	Assert::equal($expectedRoles[$username], $identity->getRoles());
}
