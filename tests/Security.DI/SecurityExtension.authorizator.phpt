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
	roles:
		guest:
		member: [guest]
	resources:
		item:
		article: item
', 'neon'));

@eval($compiler->addConfig($config)->compile()); // @ is deprecated
$container = new Container;

$authorizator = $container->getService('security.authorizator');
Assert::type(Nette\Security\Permission::class, $authorizator);
Assert::same($authorizator, $container->getService('nette.authorizator'));

Assert::same(['guest', 'member'], $authorizator->getRoles());
Assert::same([], $authorizator->getRoleParents('guest'));
Assert::same(['guest'], $authorizator->getRoleParents('member'));

Assert::same(['item', 'article'], $authorizator->getResources());
Assert::false($authorizator->resourceInheritsFrom('item', 'article'));
Assert::true($authorizator->resourceInheritsFrom('article', 'item'));
