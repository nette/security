<?php

declare(strict_types=1);

use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Security\SimpleIdentity;
use Tester\Assert;

require __DIR__ . '/../bootstrap.php';

// missing id
$response = new Nette\Http\Response;
$request = new Nette\Http\Request(new Nette\Http\UrlScript);
$storage = new CookieStorage($request, $response);
Assert::same([false, null, null], $storage->getState());

// short id
$request = new Nette\Http\Request(new Nette\Http\UrlScript, cookies: ['userid' => 'short']);
$storage = new CookieStorage($request, $response);
Assert::same([false, null, null], $storage->getState());

// correct id
$id = '123456789123456';
$request = new Nette\Http\Request(new Nette\Http\UrlScript, cookies: ['userid' => $id]);
$storage = new CookieStorage($request, $response);
Assert::equal([true, new SimpleIdentity($id), null], $storage->getState());

// custom cookie
$request = new Nette\Http\Request(new Nette\Http\UrlScript, cookies: ['foo' => $id]);
$storage = new CookieStorage($request, $response);
$storage->setCookieParameters('foo');
Assert::equal([true, new SimpleIdentity($id), null], $storage->getState());
