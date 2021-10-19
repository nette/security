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

eval($compiler->compile());
$container = new Container;

Assert::type(Nette\Bridges\SecurityHttp\SessionStorage::class, $container->getService('security.userStorage'));
Assert::type(Nette\Security\User::class, $container->getService('security.user'));

// aliases
Assert::same($container->getService('security.userStorage'), $container->getService('nette.userStorage'));
Assert::same($container->getService('security.user'), $container->getService('user'));
