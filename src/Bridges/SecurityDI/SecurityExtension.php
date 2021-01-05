<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Bridges\SecurityDI;

use Nette;
use Nette\Schema\Expect;


/**
 * Security extension for Nette DI.
 */
class SecurityExtension extends Nette\DI\CompilerExtension
{
	/** @var bool */
	private $debugMode;


	public function __construct(bool $debugMode = false)
	{
		$this->debugMode = $debugMode;
	}


	public function getConfigSchema(): Nette\Schema\Schema
	{
		return Expect::structure([
			'debugger' => Expect::bool(),
			'users' => Expect::arrayOf(
				Expect::anyOf(
					Expect::string(), // user => password
					Expect::structure([ // user => password + roles + data
						'password' => Expect::string(),
						'roles' => Expect::anyOf(Expect::string(), Expect::listOf('string')),
						'data' => Expect::array(),
					])->castTo('array')
				)
			),
			'roles' => Expect::arrayOf('string|array|null')->deprecated(), // role => parent(s)
			'resources' => Expect::arrayOf('string|null')->deprecated(), // resource => parent
		]);
	}


	public function loadConfiguration()
	{
		/** @var object{debugger: bool, users: array, roles: array, resources: array} $config */
		$config = $this->config;
		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('passwords'))
			->setFactory(Nette\Security\Passwords::class);

		$storage = $builder->addDefinition($this->prefix('userStorage'))
			->setType(Nette\Security\UserStorage::class)
			->setFactory(Nette\Bridges\SecurityHttp\SessionStorage::class);

		$builder->addDefinition($this->prefix('legacyUserStorage')) // deprecated
			->setType(Nette\Security\IUserStorage::class)
			->setFactory(Nette\Http\UserStorage::class);

		$user = $builder->addDefinition($this->prefix('user'))
			->setFactory(Nette\Security\User::class);

		if ($config->users) {
			$usersList = $usersRoles = $usersData = [];
			foreach ($config->users as $username => $data) {
				$data = is_array($data) ? $data : ['password' => $data];
				$usersList[$username] = $data['password'];
				$usersRoles[$username] = $data['roles'] ?? null;
				$usersData[$username] = $data['data'] ?? [];
			}

			$builder->addDefinition($this->prefix('authenticator'))
				->setType(Nette\Security\IAuthenticator::class)
				->setFactory(Nette\Security\SimpleAuthenticator::class, [$usersList, $usersRoles, $usersData]);

			if ($this->name === 'security') {
				$builder->addAlias('nette.authenticator', $this->prefix('authenticator'));
			}
		}

		if ($config->roles || $config->resources) {
			$authorizator = $builder->addDefinition($this->prefix('authorizator'))
				->setType(Nette\Security\Authorizator::class)
				->setFactory(Nette\Security\Permission::class);

			foreach ($config->roles as $role => $parents) {
				$authorizator->addSetup('addRole', [$role, $parents]);
			}
			foreach ($config->resources as $resource => $parents) {
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


	public function beforeCompile()
	{
		$builder = $this->getContainerBuilder();

		if (
			$this->debugMode &&
			($this->config->debugger ?? $builder->getByType(\Tracy\Bar::class))
		) {
			$builder->getDefinition($this->prefix('user'))->addSetup('@Tracy\Bar::addPanel', [
				new Nette\DI\Definitions\Statement(Nette\Bridges\SecurityTracy\UserPanel::class),
			]);
		}
	}
}
