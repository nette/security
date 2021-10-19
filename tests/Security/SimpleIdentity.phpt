<?php

/**
 * Test: Nette\Security\SimpleIdentity.
 */

declare(strict_types=1);

use Nette\Security\SimpleIdentity;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


test('', function () {
	$id = new SimpleIdentity(12, 'admin', ['name' => 'John']);

	Assert::same(12, $id->getId());
	Assert::same(12, $id->id);
	Assert::same(['admin'], $id->getRoles());
	Assert::same(['admin'], $id->roles);
	Assert::same(['name' => 'John'], $id->getData());
	Assert::same(['name' => 'John'], $id->data);
	Assert::same('John', $id->name);
});


test('', function () {
	$id = new SimpleIdentity('12');
	Assert::same(12, $id->getId());


	$id = new SimpleIdentity('12345678901234567890');
	Assert::same('12345678901234567890', $id->getId());
});
