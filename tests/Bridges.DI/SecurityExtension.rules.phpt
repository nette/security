<?php declare(strict_types=1);

/**
 * Test: SecurityExtension ACL rules in configuration
 */

use Nette\Bridges\HttpDI\HttpExtension;
use Nette\Bridges\HttpDI\SessionExtension;
use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


function makeCompiler(): DI\Compiler
{
	$compiler = new DI\Compiler;
	$compiler->addExtension('foo', new HttpExtension);
	$compiler->addExtension('bar', new SessionExtension);
	$compiler->addExtension('security', new SecurityExtension);
	return $compiler;
}


$loader = new Nette\DI\Config\Loader;
$config = $loader->load(Tester\FileMock::create(<<<'XX'

	security:
		roles:
			guest:
			registered: [guest]
			admin: [registered]
		resources:
			article:
			comment:
		rules:
			allow:
				- [guest, article, view]
				- [registered, comment, [add, edit]]
				- [admin]
			deny:
				- [admin, comment, spam]

	XX, 'neon'));

eval(makeCompiler()->addConfig($config)->setClassName('Container1')->compile());
$container = new Container1;

$authorizator = $container->getService('security.authorizator');
Assert::type(Nette\Security\Permission::class, $authorizator);

Assert::true($authorizator->isAllowed('guest', 'article', 'view'));
Assert::false($authorizator->isAllowed('guest', 'article', 'edit'));
Assert::true($authorizator->isAllowed('registered', 'article', 'view')); // inherited from guest
Assert::true($authorizator->isAllowed('registered', 'comment', 'add'));
Assert::true($authorizator->isAllowed('registered', 'comment', 'edit'));
Assert::false($authorizator->isAllowed('registered', 'comment', 'delete'));
Assert::true($authorizator->isAllowed('admin', 'article', 'edit')); // allowed everything
Assert::false($authorizator->isAllowed('admin', 'comment', 'spam')); // explicit deny wins


// rules alone are enough to register the authorizator
$config = $loader->load(Tester\FileMock::create(<<<'XX'

	security:
		rules:
			allow:
				- [null, null, view]

	XX, 'neon'));

eval(makeCompiler()->addConfig($config)->setClassName('Container2')->compile());
$container = new Container2;

$authorizator = $container->getService('security.authorizator');
Assert::true($authorizator->isAllowed(null, null, 'view'));
Assert::false($authorizator->isAllowed(null, null, 'edit'));


// malformed rules are rejected at config time
Assert::exception(
	fn() => makeCompiler()->addConfig($loader->load(Tester\FileMock::create(<<<'XX'

		security:
			rules:
				allow:
					- [guest, article, view, edit]

		XX, 'neon')))->compile(),
	Nette\DI\InvalidConfigurationException::class,
);

Assert::exception(
	fn() => makeCompiler()->addConfig($loader->load(Tester\FileMock::create(<<<'XX'

		security:
			rules:
				allow:
					- {roles: guest, resources: article}

		XX, 'neon')))->compile(),
	Nette\DI\InvalidConfigurationException::class,
);
