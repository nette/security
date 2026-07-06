<?php declare(strict_types=1);

/**
 * Test: Nette\Bridges\SecurityHttp\SessionStorage expiration and sliding expiration.
 */

use Nette\Bridges\SecurityHttp\SessionStorage;
use Nette\Http\Session;
use Nette\Security\SimpleIdentity;
use Nette\Security\User;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


// Setup environment for session
ob_start();


test('Session stays authenticated without expiration set', function () {
	$request = new Nette\Http\Request(new Nette\Http\UrlScript('http://localhost'));
	$response = new Nette\Http\Response;
	$session = new Session($request, $response);
	$storage = new SessionStorage($session);

	$storage->saveAuthentication(new SimpleIdentity('john'));
	Assert::equal([true, new SimpleIdentity('john'), null], $storage->getState());

	// Create new storage instance (simulates new request)
	$storage2 = new SessionStorage($session);
	Assert::equal([true, new SimpleIdentity('john'), null], $storage2->getState());
});


test('Expiration with clearIdentity removes identity on timeout', function () {
	$request = new Nette\Http\Request(new Nette\Http\UrlScript('http://localhost'));
	$response = new Nette\Http\Response;
	$session = new Session($request, $response);
	$storage = new SessionStorage($session);

	$storage->setExpiration('1 second', true);
	$storage->saveAuthentication(new SimpleIdentity('john'));

	Assert::true($storage->getState()[0]);
	Assert::notNull($storage->getState()[1]);

	// Wait for expiration
	sleep(2);

	// Create new storage (simulates new request after expiration)
	$storage2 = new SessionStorage($session);
	[$authenticated, $identity, $reason] = $storage2->getState();

	Assert::false($authenticated);
	Assert::null($identity); // Identity cleared
	Assert::same(User::LogoutInactivity, $reason);
});


test('Expiration without clearIdentity keeps identity on timeout', function () {
	$request = new Nette\Http\Request(new Nette\Http\UrlScript('http://localhost'));
	$response = new Nette\Http\Response;
	$session = new Session($request, $response);
	$storage = new SessionStorage($session);

	$storage->setExpiration('1 second', false);
	$storage->saveAuthentication(new SimpleIdentity('john'));

	Assert::equal([true, new SimpleIdentity('john'), null], $storage->getState());

	// Wait for expiration
	sleep(2);

	// Create new storage (simulates new request after expiration)
	$storage2 = new SessionStorage($session);
	[$authenticated, $identity, $reason] = $storage2->getState();

	Assert::false($authenticated);
	Assert::equal(new SimpleIdentity('john'), $identity); // Identity still available
	Assert::same(User::LogoutInactivity, $reason);
});


test('Sliding expiration extends session on activity', function () {
	$request = new Nette\Http\Request(new Nette\Http\UrlScript('http://localhost'));
	$response = new Nette\Http\Response;
	$session = new Session($request, $response);
	$storage = new SessionStorage($session);

	$storage->setExpiration('2 seconds');
	$storage->saveAuthentication(new SimpleIdentity('john'));

	// Activity after 1 second (within window)
	sleep(1);
	$storage2 = new SessionStorage($session);
	Assert::true($storage2->getState()[0]); // Still authenticated

	// Another activity after 1 second (total 2 seconds from login, but 1 from last activity)
	sleep(1);
	$storage3 = new SessionStorage($session);
	Assert::true($storage3->getState()[0]); // Still authenticated (sliding extended it)

	// Wait 3 seconds without activity (exceeds window)
	sleep(3);
	$storage4 = new SessionStorage($session);
	[$authenticated, $identity, $reason] = $storage4->getState();

	Assert::false($authenticated);
	Assert::same(User::LogoutInactivity, $reason);
});


test('setExpiration(null) disables expiration', function () {
	$request = new Nette\Http\Request(new Nette\Http\UrlScript('http://localhost'));
	$response = new Nette\Http\Response;
	$session = new Session($request, $response);
	$storage = new SessionStorage($session);

	$storage->setExpiration('1 second');
	$storage->saveAuthentication(new SimpleIdentity('john'));

	// Disable expiration
	$storage->setExpiration(null);

	// Wait beyond original limit
	sleep(2);

	// Still authenticated
	$storage2 = new SessionStorage($session);
	Assert::true($storage2->getState()[0]);
});
