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

	/** @var Nette\Security\User */
	private $user;


	public function __construct(Nette\Security\User $user)
	{
		$this->user = $user;
	}


	/**
	 * Renders tab.
	 */
	public function getTab(): ?string
	{
		if (headers_sent() && !session_id()) {
			return null;
		}

		ob_start(function () {});
		$user = $this->user;
		require __DIR__ . '/templates/UserPanel.tab.phtml';
		return ob_get_clean();
	}


	/**
	 * Renders panel.
	 */
	public function getPanel(): string
	{
		ob_start(function () {});
		$user = $this->user;
		require __DIR__ . '/templates/UserPanel.panel.phtml';
		return ob_get_clean();
	}
}
