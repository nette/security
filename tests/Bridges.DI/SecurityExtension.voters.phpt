<?php declare(strict_types=1);

/**
 * Test: SecurityExtension passes voters to the user
 */

use Nette\Bridges\HttpDI\{HttpExtension, SessionExtension};
use Nette\Bridges\SecurityDI\SecurityExtension;
use Nette\DI;
use Nette\Security\{Principal, SimpleIdentity, User, Vote, Voter};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


class AdminVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, ?string $privilege): Vote
	{
		return Vote::allowIf($principal->isInRole('admin'));
	}
}


class LegacyAuthorizator implements Nette\Security\Authorizator
{
	public function isAllowed(?string $role, ?string $resource, ?string $privilege): bool
	{
		return $role === 'editor';
	}
}


function createContainer(string $neon, string $class): User
{
	$compiler = new DI\Compiler;
	$compiler->addExtension('foo', new HttpExtension);
	$compiler->addExtension('bar', new SessionExtension);
	$compiler->addExtension('security', new SecurityExtension);
	$config = (new DI\Config\Loader)->load(Tester\FileMock::create($neon, 'neon'));
	eval($compiler->addConfig($config)->setClassName($class)->compile());
	$user = (new $class)->getByType(User::class);
	$user->getStorage()->setNamespace($class);
	return $user;
}


test('the ACL and the voter services', function () {
	$user = createContainer(<<<'XX'
		security:
			roles:
				guest:
			resources:
				article:
			rules:
				allow:
					- [guest, article, view]

		services:
			- AdminVoter
			- {factory: AdminVoter, autowired: false}
		XX, 'Container1');

	Assert::true($user->isAllowed('article', 'view'));
	Assert::false($user->isAllowed('article', 'edit'));

	$user->login(new SimpleIdentity(1, ['admin']));
	Assert::true($user->isAllowed('article', 'edit'));
	Assert::true($user->isAllowed(new stdClass));
});


test('the role-based authorizator of the application', function () {
	$neon = <<<'XX'
		services:
			- LegacyAuthorizator
		XX;
	$user = @createContainer($neon, 'Container2'); // @ setAuthorizator() is deprecated

	Assert::false($user->isAllowed('article'));

	$user->login(new SimpleIdentity(1, ['editor']));
	Assert::true($user->isAllowed('article'));
});


test('multiple role-based authorizators', function () {
	Assert::exception(
		fn() => createContainer(<<<'XX'
			services:
				a: LegacyAuthorizator
				b: LegacyAuthorizator
			XX, 'Container3'),
		DI\InvalidConfigurationException::class,
		'Multiple services implement Nette\Security\Authorizator: a, b. Turn them into voters.',
	);
});
