<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityTracy;

use Nette;
use Tracy;


/**
 * User panel for Debugger Bar.
 */
class UserPanel extends Nette\Object implements Tracy\IBarPanel
{
	/** @var Nette\Security\User */
	private $user;


	public function __construct(Nette\Security\User $user)
	{
		$this->user = $user;
	}


	/**
	 * Renders tab.
	 * @return string
	 */
	public function getTab()
	{
		if (headers_sent() && !session_id()) {
			return;
		}

		ob_start();
		$user = $this->user;
		require __DIR__ . '/templates/UserPanel.tab.phtml';
		return ob_get_clean();
	}


	/**
	 * Renders panel.
	 * @return string
	 */
	public function getPanel()
	{
		ob_start();
		$user = $this->user;
		require __DIR__ . '/templates/UserPanel.panel.phtml';
		return ob_get_clean();
	}

}
