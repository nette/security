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

eval($compiler->compile(array(), 'Container1'));
$container = new Container1;

Assert::type('Nette\Http\UserStorage', $container->getService('security.userStorage'));
Assert::type('Nette\Security\User', $container->getService('security.user'));

// aliases
Assert::same($container->getService('security.userStorage'), $container->getService('nette.userStorage'));
Assert::same($container->getService('security.user'), $container->getService('user'));
