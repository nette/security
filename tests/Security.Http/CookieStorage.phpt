<?php

/**
 * Test: Nette\Bridges\SecurityHttp\CookieStorage
 */

declare(strict_types=1);

use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\UrlScript;
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

// authenticate
$storage->saveAuthentication(new SimpleIdentity($uid));
[$authenticated, $identity, $reason] = $storage->getState();
Assert::true($authenticated);
Assert::equal($uid, $identity->getId());
Assert::null($reason);

// clear authentication
$storage->clearAuthentication(false); // clearIdentity parameter is ignored for cookie storage
[$authenticated, $identity, $reason] = $storage->getState();
Assert::equal([false, null, null], $storage->getState());
