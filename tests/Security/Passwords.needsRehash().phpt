<?php

/**
 * Test: Nette\Security\Passwords::needsRehash()
 */

declare(strict_types=1);

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::true((new Passwords(PASSWORD_BCRYPT))->needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::false((new Passwords(PASSWORD_BCRYPT, ['cost' => 5]))->needsRehash('$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
