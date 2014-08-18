<?php

/**
 * This file is part of the Nette Framework (http://nette.org)
 * Copyright (c) 2004 David Grudl (http://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityDI;

use Nette;


/**
 * Security extension for Nette DI.
 *
 * @author     David Grudl
 */
class SecurityExtension extends Nette\DI\CompilerExtension
{
	public $defaults = array(
		'debugger' => TRUE,
		'users' => array(), // of [user => password] or [user => ['password' => password, 'roles' => [role]]]
		'roles' => array(), // of [role => parents]
		'resources' => array(), // of [resource => parents]
	);

	/** @var bool */
	private $debugMode;


	public function __construct($debugMode = FALSE)
	{
		$this->debugMode = $debugMode;
	}


	public function loadConfiguration()
	{
		$config = $this->validateConfig($this->defaults);
		$container = $this->getContainerBuilder();

		$container->addDefinition($this->prefix('userStorage'))
			->setClass('Nette\Security\IUserStorage')
			->setFactory('Nette\Http\UserStorage');

		$user = $container->addDefinition($this->prefix('user'))
			->setClass('Nette\Security\User');

		if ($this->debugMode && $config['debugger']) {
			$user->addSetup('@Tracy\Bar::addPanel', array(
				new Nette\DI\Statement('Nette\Bridges\SecurityTracy\UserPanel')
			));
		}

		if ($config['users']) {
			$usersList = $usersRoles = array();
			foreach ($config['users'] as $username => $data) {
				$data = is_array($data) ? $data : array('password' => $data);
				$this->validateConfig(array('password' => NULL, 'roles' => NULL), $data, $this->prefix("security.users.$username"));
				$usersList[$username] = $data['password'];
				$usersRoles[$username] = isset($data['roles']) ? $data['roles'] : NULL;
			}

			$container->addDefinition($this->prefix('authenticator'))
				->setClass('Nette\Security\IAuthenticator')
				->setFactory('Nette\Security\SimpleAuthenticator', array($usersList, $usersRoles));

			if ($this->name === 'security') {
				$container->addAlias('nette.authenticator', $this->prefix('authenticator'));
			}
		}

		if ($config['roles'] || $config['resources']) {
			$authorizator = $container->addDefinition($this->prefix('authorizator'))
				->setClass('Nette\Security\IAuthorizator')
				->setFactory('Nette\Security\Permission');

			foreach ($config['roles'] as $role => $parents) {
				$authorizator->addSetup('addRole', array($role, $parents));
			}
			foreach ($config['resources'] as $resource => $parents) {
				$authorizator->addSetup('addResource', array($resource, $parents));
			}

			if ($this->name === 'security') {
				$container->addAlias('nette.authorizator', $this->prefix('authorizator'));
			}
		}

		if ($this->name === 'security') {
			$container->addAlias('user', $this->prefix('user'));
			$container->addAlias('nette.userStorage', $this->prefix('userStorage'));
		}
	}

}
