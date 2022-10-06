<?php

declare(strict_types=1);

use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Security\SimpleIdentity;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';

// short id
$request = new Nette\Http\Request(new Nette\Http\UrlScript);
$response = Mockery::mock(Nette\Http\IResponse::class);
$storage = new CookieStorage($request, $response);
Assert::exception(function () use ($storage) {
	$storage->saveAuthentication(new SimpleIdentity('short'));
}, LogicException::class);

// correct id
$id = '123456789123456';
$response->expects()->setCookie('userid', $id, null, null, null, false, true, 'Lax');
$storage->saveAuthentication(new SimpleIdentity($id));
Mockery::close();

// clear id
$response->expects()->deleteCookie('userid', null, null);
$storage->clearAuthentication(true);
Mockery::close();
