<?php declare(strict_types=1);

/**
 * Test: Nette\Security\SimpleIdentity serialization.
 */

use Nette\Security\SimpleIdentity;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


class MyIdentity extends SimpleIdentity
{
	public string $email = '';
	protected ?string $token = null;
	private string $secret = '';


	public function getToken(): ?string
	{
		return $this->token;
	}


	public function setSecret(string $secret): void
	{
		$this->secret = $secret;
	}


	public function getSecret(): string
	{
		return $this->secret;
	}
}


test('plain identity', function () {
	$identity = new SimpleIdentity(12, 'admin', ['name' => 'John', 'note' => null]);
	Assert::same(['id' => 12, 'roles' => ['admin'], 'data' => ['name' => 'John', 'note' => null]], $identity->__serialize());

	$res = unserialize(serialize($identity));
	Assert::type(SimpleIdentity::class, $res);
	Assert::same(12, $res->getId());
	Assert::same(['admin'], $res->getRoles());
	Assert::same(['name' => 'John', 'note' => null], $res->getData());
});


test('subclass keeps its public and protected properties', function () {
	$identity = new MyIdentity('007', ['admin'], ['name' => 'John']);
	$identity->email = 'john@example.com';
	(fn() => $this->token = 'abc')->call($identity);
	$identity->setSecret('private');

	$res = unserialize(serialize($identity));
	Assert::type(MyIdentity::class, $res);
	Assert::same('007', $res->getId());
	Assert::same(['admin'], $res->getRoles());
	Assert::same(['name' => 'John'], $res->getData());
	Assert::same('john@example.com', $res->email);
	Assert::same('abc', $res->getToken());
	Assert::same('', $res->getSecret()); // private properties of a subclass are its own business
});


test('3.x payload of SimpleIdentity', function () {
	$res = unserialize(
		'O:29:"Nette\Security\SimpleIdentity":3:{'
		. "s:27:\"\0Nette\\Security\\Identity\0id\";s:3:\"007\";"
		. "s:30:\"\0Nette\\Security\\Identity\0roles\";a:2:{i:0;s:5:\"admin\";i:1;s:6:\"editor\";}"
		. "s:29:\"\0Nette\\Security\\Identity\0data\";a:2:{s:4:\"name\";s:4:\"John\";s:4:\"note\";N;}"
		. '}',
	);
	Assert::same(SimpleIdentity::class, $res::class);
	Assert::same('007', $res->getId());
	Assert::same(['admin', 'editor'], $res->getRoles());
	Assert::same(['name' => 'John', 'note' => null], $res->getData());
});


test('3.x payload of Identity', function () {
	$res = unserialize(
		'O:23:"Nette\Security\Identity":3:{'
		. "s:27:\"\0Nette\\Security\\Identity\0id\";i:12;"
		. "s:30:\"\0Nette\\Security\\Identity\0roles\";a:1:{i:0;s:5:\"admin\";}"
		. "s:29:\"\0Nette\\Security\\Identity\0data\";a:1:{s:4:\"note\";N;}"
		. '}',
	);
	Assert::same(SimpleIdentity::class, $res::class);
	Assert::same(12, $res->getId());
	Assert::same(['admin'], $res->getRoles());
	Assert::same(['note' => null], $res->getData());
});


test('3.x payload of a subclass', function () {
	$res = unserialize(
		'O:10:"MyIdentity":6:{'
		. 's:5:"email";s:16:"john@example.com";'
		. "s:8:\"\0*\0token\";s:3:\"abc\";"
		. "s:18:\"\0MyIdentity\0secret\";s:7:\"private\";"
		. "s:27:\"\0Nette\\Security\\Identity\0id\";s:3:\"007\";"
		. "s:30:\"\0Nette\\Security\\Identity\0roles\";a:1:{i:0;s:5:\"admin\";}"
		. "s:29:\"\0Nette\\Security\\Identity\0data\";a:1:{s:4:\"note\";N;}"
		. '}',
	);
	Assert::type(MyIdentity::class, $res);
	Assert::same('007', $res->getId());
	Assert::same(['admin'], $res->getRoles());
	Assert::same(['note' => null], $res->getData());
	Assert::same('john@example.com', $res->email);
	Assert::same('abc', $res->getToken());
	Assert::same('', $res->getSecret());
});


test('payload without ID', function () {
	Assert::exception(
		fn() => unserialize('O:29:"Nette\Security\SimpleIdentity":1:{s:5:"roles";a:0:{}}'),
		Nette\InvalidStateException::class,
		'The serialized identity has no ID.',
	);
});


test('a property the class does not have is ignored', function () {
	$res = unserialize('O:29:"Nette\Security\SimpleIdentity":2:{s:2:"id";i:1;s:5:"email";s:1:"x";}');
	Assert::same([], $res->getData());
	Assert::same(['id' => 1, 'roles' => [], 'data' => []], $res->__serialize());
});
