<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityDI;

use Nette;


/**
 * Security extension for Nette DI.
 */
class SecurityExtension extends Nette\DI\CompilerExtension
{
	public $defaults = [
		'debugger' => TRUE,
		'users' => [], // of [user => password] or [user => ['password' => password, 'roles' => [role]]]
		'roles' => [], // of [role => parent(s)]
		'resources' => [], // of [resource => parent]
	];

	/** @var bool */
	private $debugMode;


	public function __construct(bool $debugMode = FALSE)
	{
		$this->debugMode = $debugMode;
	}


	public function loadConfiguration()
	{
		$config = $this->validateConfig($this->defaults);
		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('userStorage'))
			->setClass(Nette\Security\IUserStorage::class)
			->setFactory(Nette\Http\UserStorage::class);

		$user = $builder->addDefinition($this->prefix('user'))
			->setClass(Nette\Security\User::class);

		if ($this->debugMode && $config['debugger']) {
			$user->addSetup('@Tracy\Bar::addPanel', [
				new Nette\DI\Statement(Nette\Bridges\SecurityTracy\UserPanel::class),
			]);
		}

		if ($config['users']) {
			$usersList = $usersRoles = [];
			foreach ($config['users'] as $username => $data) {
				$data = is_array($data) ? $data : ['password' => $data];
				$this->validateConfig(['password' => NULL, 'roles' => NULL], $data, $this->prefix("security.users.$username"));
				$usersList[$username] = $data['password'];
				$usersRoles[$username] = $data['roles'] ?? NULL;
			}

			$builder->addDefinition($this->prefix('authenticator'))
				->setClass(Nette\Security\IAuthenticator::class)
				->setFactory(Nette\Security\SimpleAuthenticator::class, [$usersList, $usersRoles]);

			if ($this->name === 'security') {
				$builder->addAlias('nette.authenticator', $this->prefix('authenticator'));
			}
		}

		if ($config['roles'] || $config['resources']) {
			$authorizator = $builder->addDefinition($this->prefix('authorizator'))
				->setClass(Nette\Security\IAuthorizator::class)
				->setFactory(Nette\Security\Permission::class);

			foreach ($config['roles'] as $role => $parents) {
				$authorizator->addSetup('addRole', [$role, $parents]);
			}
			foreach ($config['resources'] as $resource => $parents) {
				$authorizator->addSetup('addResource', [$resource, $parents]);
			}

			if ($this->name === 'security') {
				$builder->addAlias('nette.authorizator', $this->prefix('authorizator'));
			}
		}

		if ($this->name === 'security') {
			$builder->addAlias('user', $this->prefix('user'));
			$builder->addAlias('nette.userStorage', $this->prefix('userStorage'));
		}
	}

}
