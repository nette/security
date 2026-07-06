<?php declare(strict_types=1);

/**
 * Test: Nette\Security\Passwords::verify()
 */

use Nette\Security\Passwords;
use Tester\Assert;


require __DIR__ . '/../bootstrap.php';


Assert::true((new Passwords)->verify('dg', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::true((new Passwords)->verify('dg', '$2x$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
Assert::false((new Passwords)->verify('dgx', '$2y$05$123456789012345678901uTj3G.8OMqoqrOMca1z/iBLqLNaWe6DK'));
