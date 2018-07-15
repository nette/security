<?php

/**
 * Test: Nette\Security\Passwords non-static usage
 */

declare(strict_types=1);

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::truthy(
	preg_match('#^\$2.\$\d\d\$.{53}\z#', (new Passwords)->hash(''))
);

Assert::true((new Passwords)->needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::false((new Passwords)->needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK', ['cost' => 5]));

Assert::true((new Passwords)->verify('dg', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::true((new Passwords)->verify('dg', '$2x$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::false((new Passwords)->verify('dgx', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
