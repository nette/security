<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Identity (deprecated, behaves like SimpleIdentity).
 */

use Nette\Security\Identity;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


test('deprecated Identity behaves like SimpleIdentity', function () {
	$id = new Identity(12, 'admin', ['name' => 'John']);
	Assert::same(12, $id->id);
	Assert::same(['admin'], $id->roles);
	Assert::same('John', $id->name);

	// numeric string id is coerced to int, oversized stays string
	Assert::same(12, (new Identity('12'))->getId());
	Assert::same('12345678901234567890', (new Identity('12345678901234567890'))->getId());
});
