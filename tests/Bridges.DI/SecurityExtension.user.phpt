<?php declare(strict_types=1);

/**
 * Test: SecurityExtension
 */

use Nette\Bridges\HttpDI\{HttpExtension, SessionExtension};
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
