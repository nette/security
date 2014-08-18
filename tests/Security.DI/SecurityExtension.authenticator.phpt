<?php

/**
 * Test: SecurityExtension
 */

use Nette\DI,
	Nette\Bridges\HttpDI\HttpExtension,
	Nette\Bridges\HttpDI\SessionExtension,
	Nette\Bridges\SecurityDI\SecurityExtension,
	Tester\Assert;


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

eval($compiler->compile($config, 'Container1'));
$container = new Container1;

$authenticator = $container->getService('security.authenticator');
Assert::type('Nette\Security\SimpleAuthenticator', $authenticator);
Assert::same($authenticator, $container->getService('nette.authenticator'));

$userList = array(
	'john' => 'john123',
	'admin' => 'admin123',
	'user' => 'user123',
	'moderator' => 'moderator123',
);
$expectedRoles = array(
	'john' => array(),
	'admin' => array('admin', 'user'),
	'user' => array(),
	'moderator' => array('moderator'),
);

foreach ($userList as $username => $password) {
	$identity = $authenticator->authenticate(array($username, $password));
	Assert::equal($username, $identity->getId());
	Assert::equal($expectedRoles[$username], $identity->getRoles());
}
