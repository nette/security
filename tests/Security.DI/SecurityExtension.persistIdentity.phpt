<?php declare(strict_types=1);

/**
 * Test: SecurityExtension persistIdentity
 */

use Nette\Bridges\HttpDI\HttpExtension;
use Nette\Bridges\HttpDI\SessionExtension;
use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


test('defaults to true', function () {
	$compiler = new DI\Compiler;
	$compiler->addExtension('foo', new HttpExtension);
	$compiler->addExtension('bar', new SessionExtension);
	$compiler->addExtension('security', new SecurityExtension);
	$compiler->setClassName('ContainerDefault');

	eval($compiler->compile());
	$container = new ContainerDefault;

	Assert::true($container->getService('security.user')->persistIdentity);
});


test('disabled via configuration', function () {
	$compiler = new DI\Compiler;
	$compiler->addExtension('foo', new HttpExtension);
	$compiler->addExtension('bar', new SessionExtension);
	$compiler->addExtension('security', new SecurityExtension);
	$compiler->setClassName('ContainerDisabled');

	$loader = new Nette\DI\Config\Loader;
	$config = $loader->load(Tester\FileMock::create('
security:
	authentication:
		persistIdentity: false
', 'neon'));

	eval($compiler->addConfig($config)->compile());
	$container = new ContainerDisabled;

	Assert::false($container->getService('security.user')->persistIdentity);
});
