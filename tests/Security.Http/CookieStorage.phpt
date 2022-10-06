<?php

/**
 * Test: Nette\Bridges\SecurityHttp\CookieStorage
 */

declare(strict_types=1);

use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\UrlScript;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Utils\Random;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';

$request = new Request(new UrlScript());
$response = new Response();
$storage = new CookieStorage($request, $response);

$uid = Random::generate(15);

// initially, there is nothing stored
Assert::equal([false, null, null], $storage->getState());


// save authentication

final class ExtendingStorageIdentity extends SimpleIdentity {}
final class ImplementingStorageIdentity implements IIdentity {
	public function __construct(private string|int $id, private array $roles = [], private array $data = []) {}
	public function getId(): string|int { return $this->id; }
	public function getRoles(): array { return $this->roles; }
	public function getData(): array { return $this->data; }
}
$testWithIdentity = function (IIdentity $identity) use ($storage, $uid): void {
	$storage->saveAuthentication($identity);
	[$authenticated, $identity, $reason] = $storage->getState();
	Assert::true($authenticated);
	\assert($identity instanceof IIdentity);
	Assert::equal($uid, $identity->getId());

	// on these discrepancies, see https://forum.nette.org/en/35470-let-s-talk-about-cookie-storage
	Assert::equal([], $identity->getRoles()); // whatever is passed, roles should get removed
	Assert::equal([], $identity->getData()); // whatever is passed, data should get removed
	Assert::type(SimpleIdentity::class, $identity); // whatever is passed, SimpleIdentity is always returned

	Assert::null($reason); // always null
};

// with just ID
$testWithIdentity(new SimpleIdentity($uid));
$testWithIdentity(new ExtendingStorageIdentity($uid));
$testWithIdentity(new ImplementingStorageIdentity($uid));

// roles & data should get removed (currently expected behavior for CookieStorage, see notes in the closure)
$roles = ['editor'];
$data = ['email' => 'john.doe@example.com'];
$testWithIdentity(new SimpleIdentity($uid, $roles, $data));
$testWithIdentity(new ExtendingStorageIdentity($uid, $roles, $data));
$testWithIdentity(new ImplementingStorageIdentity($uid, $roles, $data));


// clear authentication
$storage->clearAuthentication(false); // clearIdentity parameter is ignored for cookie storage
[$authenticated, $identity, $reason] = $storage->getState();
Assert::equal([false, null, null], $storage->getState());
