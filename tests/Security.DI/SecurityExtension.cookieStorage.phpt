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
$compiler->addExtension('session', new SessionExtension);
$compiler->addExtension('security', new SecurityExtension);

$loader = new Nette\DI\Config\Loader;
$config = $loader->load(Tester\FileMock::create('
security:
	authentication:
		storage: cookie
		expiration: 1 week
		cookieName: abc
		cookieDomain: xyz
		cookieSamesite: Strict
', 'neon'));

eval($compiler->addConfig($config)->compile());
$container = new Container;

$storage = $container->getService('security.userStorage');
Assert::type(Nette\Bridges\SecurityHttp\CookieStorage::class, $storage);

Assert::with($storage, function () {
	Assert::same('1 week', $this->cookieExpiration);
});
