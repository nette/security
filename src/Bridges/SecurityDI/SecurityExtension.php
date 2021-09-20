<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityDI;

use Nette;
use Nette\Schema\Expect;
use Tracy;
use function is_array;


/**
 * Security extension for Nette DI.
 *
 * @property object{
 *     debugger: bool|null,
 *     users: array<string, string|array{password: string, roles?: string|list<string>, data?: array<string, mixed>}>,
 *     roles: array<string, string|list<string>|null>,
 *     resources: array<string, string|null>,
 *     authentication: object{
 *         storage: 'session'|'cookie',
 *         expiration: string|null,
 *         persistIdentity: bool,
 *         cookieName: string|null,
 *         cookieDomain: string|null,
 *         cookieSamesite: 'Lax'|'Strict'|'None'|null,
 *     },
 * } $config
 */
class SecurityExtension extends Nette\DI\CompilerExtension
{
	public function __construct(
		private readonly bool $debugMode = false,
	) {
	}


	public function getConfigSchema(): Nette\Schema\Schema
	{
		return Expect::structure([
			'debugger' => Expect::bool(),
			'users' => Expect::arrayOf(
				Expect::anyOf(
					Expect::string()->dynamic(), // user => password
					Expect::structure([ // user => password + roles + data
						'password' => Expect::string()->dynamic(),
						'roles' => Expect::anyOf(Expect::string(), Expect::listOf('string')),
						'data' => Expect::array(),
					])->castTo('array'),
				),
			),
			'roles' => Expect::arrayOf('string|array|null'), // role => parent(s)
			'resources' => Expect::arrayOf('string|null'), // resource => parent
			'authentication' => Expect::structure([
				'storage' => Expect::anyOf('session', 'cookie')->default('session'),
				'expiration' => Expect::string()->dynamic(),
				'persistIdentity' => Expect::bool(true),
				'cookieName' => Expect::string(),
				'cookieDomain' => Expect::string(),
				'cookieSamesite' => Expect::anyOf('Lax', 'Strict', 'None'),
			]),
		]);
	}


	public function loadConfiguration(): void
	{
		$config = $this->config;
		$builder = $this->getContainerBuilder();

		$builder->addDefinition($this->prefix('passwords'))
			->setFactory(Nette\Security\Passwords::class);

		$auth = $config->authentication;
		$storage = $builder->addDefinition($this->prefix('userStorage'))
			->setType(Nette\Security\UserStorage::class)
			->setFactory([
				'session' => Nette\Bridges\SecurityHttp\SessionStorage::class,
				'cookie' => Nette\Bridges\SecurityHttp\CookieStorage::class,
			][$auth->storage]);

		if ($auth->storage === 'cookie') {
			$cookieDomain = $auth->cookieDomain === 'domain'
				? $builder::literal('$this->getByType(Nette\Http\IRequest::class)->getUrl()->getDomain(2)')
				: $auth->cookieDomain;

			$storage->addSetup('setCookieParameters', [$auth->cookieName, $cookieDomain, $auth->cookieSamesite]);
		}

		$user = $builder->addDefinition($this->prefix('user'))
			->setFactory(Nette\Security\User::class);

		if ($auth->expiration) {
			$user->addSetup('setExpiration', [$auth->expiration]);
		}

		if (!$auth->persistIdentity) {
			$user->addSetup('$persistIdentity', [false]);
		}

		if ($config->users) {
			$usersList = $usersRoles = $usersData = [];
			foreach ($config->users as $username => $data) {
				$data = is_array($data) ? $data : ['password' => $data];
				$usersList[$username] = $data['password'];
				$usersRoles[$username] = $data['roles'] ?? null;
				$usersData[$username] = $data['data'] ?? [];
			}

			$builder->addDefinition($this->prefix('authenticator'))
				->setType(Nette\Security\Authenticator::class)
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


	public function beforeCompile(): void
	{
		$builder = $this->getContainerBuilder();

		if (
			$this->debugMode &&
			($this->config->debugger ?? $builder->getByType(Tracy\Bar::class))
		) {
			$definition = $builder->getDefinition($this->prefix('user'));
			assert($definition instanceof Nette\DI\Definitions\ServiceDefinition);
			$definition->addSetup('@Tracy\Bar::addPanel', [
				new Nette\DI\Definitions\Statement(Nette\Bridges\SecurityTracy\UserPanel::class),
			]);
		}
	}
}
