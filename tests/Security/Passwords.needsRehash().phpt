<?php

/**
 * Test: Nette\Security\Passwords::needsRehash()
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::true(Passwords::needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::false(Passwords::needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK', ['cost' => 5]));
