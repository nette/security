<?php

/**
 * Test: Nette\Security\Passwords deprecated static usage
 * @phpVersion < 8
 */

declare(strict_types=1);

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


// deprecated static usage
Assert::error(function () {
	Passwords::hash('my-password');
}, E_DEPRECATED, 'Non-static method Nette\Security\Passwords::hash() should not be called statically');

Assert::truthy(
	preg_match('#^\$2y\$05\$.{53}\z#', @Passwords::hash('dg', ['cost' => 5])) // @ is not static
);


Assert::true(@Passwords::verify('dg', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK')); // @ is not static
Assert::false(@Passwords::verify('dgx', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK')); // @ is not static


Assert::true(@Passwords::needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK')); // @ is not static
