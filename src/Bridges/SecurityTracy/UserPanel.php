<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityTracy;

use Nette;
use Tracy;


/**
 * User panel for Debugger Bar.
 */
class UserPanel implements Tracy\IBarPanel
{
	use Nette\SmartObject;

	private Nette\Security\User $user;


	public function __construct(Nette\Security\User $user)
	{
		$this->user = $user;
	}


	/**
	 * Renders tab.
	 */
	public function getTab(): ?string
	{
		if (!session_id()) {
			return null;
		}

		return Nette\Utils\Helpers::capture(function () {
			$status = session_status() === PHP_SESSION_ACTIVE
				? $this->user->isLoggedIn()
				: '?';
			require __DIR__ . '/templates/UserPanel.tab.phtml';
		});
	}


	/**
	 * Renders panel.
	 */
	public function getPanel(): ?string
	{
		if (session_status() !== PHP_SESSION_ACTIVE) {
			return null;
		}

		return Nette\Utils\Helpers::capture(function () {
			$user = $this->user;
			require __DIR__ . '/templates/UserPanel.panel.phtml';
		});
	}
}
