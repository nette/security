<?php

declare(strict_types=1);

use Nette\Bridges\HttpDI\HttpExtension;
use Nette\Bridges\HttpDI\SessionExtension;
use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


$compiler = new DI\Compiler;
$compiler->addExtension('foo', new HttpExtension);
$compiler->addExtension('session', new SessionExtension);
$compiler->addExtension('security', new SecurityExtension);

$loader = new Nette\DI\Config\Loader;
$config = $loader->load(Tester\FileMock::create('
session:
	expiration: 1 year

security:
	authentication:
		storage: session
		expiration: 1 week
', 'neon'));

eval($compiler->addConfig($config)->compile());
$container = new Container;

Assert::type(Nette\Bridges\SecurityHttp\SessionStorage::class, $container->getService('security.userStorage'));
