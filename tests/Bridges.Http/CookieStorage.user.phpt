<?php declare(strict_types=1);

/**
 * Test: Nette\Security\User with CookieStorage.
 */

use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Security\{IIdentity, SimpleIdentity, TokenIdentity, User};
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';


function createStorage(): CookieStorage
{
	$request = new Nette\Http\Request(new Nette\Http\UrlScript, cookies: ['userid' => 'forged-token-123']);
	return new CookieStorage($request, new Nette\Http\Response);
}


function createHandler(?IIdentity $result): Nette\Security\Authenticator
{
	return new class ($result) implements Nette\Security\Authenticator, Nette\Security\IdentityHandler {
		public function __construct(
			private ?IIdentity $result,
		) {
		}


		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john');
		}


		public function sleepIdentity(IIdentity $identity): IIdentity
		{
			return $identity;
		}


		public function wakeupIdentity(IIdentity $identity): ?IIdentity
		{
			return $this->result === null || $identity->getId() !== 'forged-token-123'
				? null
				: $this->result;
		}


		public function getGuestIdentity(): ?IIdentity
		{
			return null;
		}
	};
}


test('token without an authenticator is refused', function () {
	$user = new User(createStorage());
	Assert::exception(
		fn() => $user->isLoggedIn(),
		Nette\InvalidStateException::class,
		'The user storage provides only a token%a%',
	);
	Assert::exception(fn() => $user->getId(), Nette\InvalidStateException::class);
});


test('token with an authenticator that is not IdentityHandler is refused', function () {
	$authenticator = new class implements Nette\Security\Authenticator {
		public function authenticate(string $username, string $password): IIdentity
		{
			return new SimpleIdentity('john');
		}
	};
	$user = new User(createStorage(), $authenticator);
	Assert::exception(fn() => $user->isLoggedIn(), Nette\InvalidStateException::class);
});


test('token returned unchanged by wakeupIdentity() is refused', function () {
	$user = new User(createStorage(), createHandler(new TokenIdentity('forged-token-123')));
	Assert::exception(fn() => $user->isLoggedIn(), Nette\InvalidStateException::class);
});


test('token rejected by wakeupIdentity() is not logged in', function () {
	$user = new User(createStorage(), createHandler(null));
	Assert::false($user->isLoggedIn());
	Assert::null($user->getId());
});


test('token exchanged by wakeupIdentity() logs in the real identity', function () {
	$user = new User(createStorage(), createHandler(new SimpleIdentity(123, ['admin'])));
	Assert::true($user->isLoggedIn());
	Assert::same(123, $user->getId());
	Assert::same(['admin'], $user->getRoles());
});
