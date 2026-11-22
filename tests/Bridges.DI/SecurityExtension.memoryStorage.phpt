<?php declare(strict_types=1);

use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


$compiler = new DI\Compiler;
$compiler->addExtension('security', new SecurityExtension);

$loader = new Nette\DI\Config\Loader;
$config = $loader->load(Tester\FileMock::create(<<<'XX'

	security:
		authentication:
			storage: memory
			expiration: 1 week

	XX, 'neon'));

eval($compiler->addConfig($config)->compile());
$container = new Container;

Assert::type(Nette\Security\MemoryStorage::class, $container->getService('security.userStorage'));

$user = $container->getService('security.user');
$user->login(new Nette\Security\SimpleIdentity(1));
Assert::true($user->isLoggedIn());
