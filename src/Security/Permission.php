<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * Access control list (ACL) functionality and privileges management.
 *
 * This solution is mostly based on Zend_Acl (c) Zend Technologies USA Inc. (https://www.zend.com), new BSD license
 */
class Permission implements Authorizator
{
	use Nette\SmartObject;

	/** @var array  Role storage */
	private $roles = [];

	/** @var array  Resource storage */
	private $resources = [];

	/** @var array  Access Control List rules; whitelist (deny everything to all) by default */
	private $rules = [
		'allResources' => [
			'allRoles' => [
				'allPrivileges' => [
					'type' => self::Deny,
					'assert' => null,
				],
				'byPrivilege' => [],
			],
			'byRole' => [],
		],
		'byResource' => [],
	];

	/** @var mixed */
	private $queriedRole;

	private $queriedResource;


	/********************* roles ****************d*g**/


	/**
	 * Adds a Role to the list. The most recently added parent
	 * takes precedence over parents that were previously added.
	 * @param  string|array $parents
	 * @throws Nette\InvalidArgumentException
	 * @throws Nette\InvalidStateException
	 * @return static
	 */
	public function addRole(string $role, $parents = null)
	{
		$this->checkRole($role, false);
		if (isset($this->roles[$role])) {
			throw new Nette\InvalidStateException("Role '$role' already exists in the list.");
		}

		$roleParents = [];

		if ($parents !== null) {
			if (!is_array($parents)) {
				$parents = [$parents];
			}

			foreach ($parents as $parent) {
				$this->checkRole($parent);
				$roleParents[$parent] = true;
				$this->roles[$parent]['children'][$role] = true;
			}
		}

		$this->roles[$role] = [
			'parents' => $roleParents,
			'children' => [],
		];

		return $this;
	}


	/**
	 * Returns true if the Role exists in the list.
	 */
	public function hasRole(string $role): bool
	{
		$this->checkRole($role, false);
		return isset($this->roles[$role]);
	}


	/**
	 * Checks whether Role is valid and exists in the list.
	 * @throws Nette\InvalidStateException
	 */
	private function checkRole(string $role, bool $exists = true): void
	{
		if ($role === '') {
			throw new Nette\InvalidArgumentException('Role must be a non-empty string.');

		} elseif ($exists && !isset($this->roles[$role])) {
			throw new Nette\InvalidStateException("Role '$role' does not exist.");
		}
	}


	/**
	 * Returns all Roles.
	 */
	public function getRoles(): array
	{
		return array_keys($this->roles);
	}


	/**
	 * Returns existing Role's parents ordered by ascending priority.
	 */
	public function getRoleParents(string $role): array
	{
		$this->checkRole($role);
		return array_keys($this->roles[$role]['parents']);
	}


	/**
	 * Returns true if $role inherits from $inherit. If $onlyParents is true,
	 * then $role must inherit directly from $inherit.
	 * @throws Nette\InvalidStateException
	 */
	public function roleInheritsFrom(string $role, string $inherit, bool $onlyParents = false): bool
	{
		$this->checkRole($role);
		$this->checkRole($inherit);

		$inherits = isset($this->roles[$role]['parents'][$inherit]);

		if ($inherits || $onlyParents) {
			return $inherits;
		}

		foreach ($this->roles[$role]['parents'] as $parent => $foo) {
			if ($this->roleInheritsFrom($parent, $inherit)) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Removes the Role from the list.
	 *
	 * @throws Nette\InvalidStateException
	 * @return static
	 */
	public function removeRole(string $role)
	{
		$this->checkRole($role);

		foreach ($this->roles[$role]['children'] as $child => $foo) {
			unset($this->roles[$child]['parents'][$role]);
		}

		foreach ($this->roles[$role]['parents'] as $parent => $foo) {
			unset($this->roles[$parent]['children'][$role]);
		}

		unset($this->roles[$role]);

		foreach ($this->rules['allResources']['byRole'] as $roleCurrent => $rules) {
			if ($role === $roleCurrent) {
				unset($this->rules['allResources']['byRole'][$roleCurrent]);
			}
		}

		foreach ($this->rules['byResource'] as $resourceCurrent => $visitor) {
			if (isset($visitor['byRole'])) {
				foreach ($visitor['byRole'] as $roleCurrent => $rules) {
					if ($role === $roleCurrent) {
						unset($this->rules['byResource'][$resourceCurrent]['byRole'][$roleCurrent]);
					}
				}
			}
		}

		return $this;
	}


	/**
	 * Removes all Roles from the list.
	 *
	 * @return static
	 */
	public function removeAllRoles()
	{
		$this->roles = [];

		foreach ($this->rules['allResources']['byRole'] as $roleCurrent => $rules) {
			unset($this->rules['allResources']['byRole'][$roleCurrent]);
		}

		foreach ($this->rules['byResource'] as $resourceCurrent => $visitor) {
			foreach ($visitor['byRole'] as $roleCurrent => $rules) {
				unset($this->rules['byResource'][$resourceCurrent]['byRole'][$roleCurrent]);
			}
		}

		return $this;
	}


	/********************* resources ****************d*g**/


	/**
	 * Adds a Resource having an identifier unique to the list.
	 *
	 * @throws Nette\InvalidArgumentException
	 * @throws Nette\InvalidStateException
	 * @return static
	 */
	public function addResource(string $resource, ?string $parent = null)
	{
		$this->checkResource($resource, false);

		if (isset($this->resources[$resource])) {
			throw new Nette\InvalidStateException("Resource '$resource' already exists in the list.");
		}

		if ($parent !== null) {
			$this->checkResource($parent);
			$this->resources[$parent]['children'][$resource] = true;
		}

		$this->resources[$resource] = [
			'parent' => $parent,
			'children' => [],
		];

		return $this;
	}


	/**
	 * Returns true if the Resource exists in the list.
	 */
	public function hasResource(string $resource): bool
	{
		$this->checkResource($resource, false);
		return isset($this->resources[$resource]);
	}


	/**
	 * Checks whether Resource is valid and exists in the list.
	 * @throws Nette\InvalidStateException
	 */
	private function checkResource(string $resource, bool $exists = true): void
	{
		if ($resource === '') {
			throw new Nette\InvalidArgumentException('Resource must be a non-empty string.');

		} elseif ($exists && !isset($this->resources[$resource])) {
			throw new Nette\InvalidStateException("Resource '$resource' does not exist.");
		}
	}


	/**
	 * Returns all Resources.
	 */
	public function getResources(): array
	{
		return array_keys($this->resources);
	}


	/**
	 * Returns true if $resource inherits from $inherit. If $onlyParents is true,
	 * then $resource must inherit directly from $inherit.
	 *
	 * @throws Nette\InvalidStateException
	 */
	public function resourceInheritsFrom(string $resource, string $inherit, bool $onlyParent = false): bool
	{
		$this->checkResource($resource);
		$this->checkResource($inherit);

		if ($this->resources[$resource]['parent'] === null) {
			return false;
		}

		$parent = $this->resources[$resource]['parent'];
		if ($inherit === $parent) {
			return true;

		} elseif ($onlyParent) {
			return false;
		}

		while ($this->resources[$parent]['parent'] !== null) {
			$parent = $this->resources[$parent]['parent'];
			if ($inherit === $parent) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Removes a Resource and all of its children.
	 *
	 * @throws Nette\InvalidStateException
	 * @return static
	 */
	public function removeResource(string $resource)
	{
		$this->checkResource($resource);

		$parent = $this->resources[$resource]['parent'];
		if ($parent !== null) {
			unset($this->resources[$parent]['children'][$resource]);
		}

		$removed = [$resource];
		foreach ($this->resources[$resource]['children'] as $child => $foo) {
			$this->removeResource($child);
			$removed[] = $child;
		}

		foreach ($removed as $resourceRemoved) {
			foreach ($this->rules['byResource'] as $resourceCurrent => $rules) {
				if ($resourceRemoved === $resourceCurrent) {
					unset($this->rules['byResource'][$resourceCurrent]);
				}
			}
		}

		unset($this->resources[$resource]);
		return $this;
	}


	/**
	 * Removes all Resources.
	 * @return static
	 */
	public function removeAllResources()
	{
		foreach ($this->resources as $resource => $foo) {
			foreach ($this->rules['byResource'] as $resourceCurrent => $rules) {
				if ($resource === $resourceCurrent) {
					unset($this->rules['byResource'][$resourceCurrent]);
				}
			}
		}

		$this->resources = [];
		return $this;
	}


	/********************* defining rules ****************d*g**/


	/**
	 * Allows one or more Roles access to [certain $privileges upon] the specified Resource(s).
	 * If $assertion is provided, then it must return true in order for rule to apply.
	 *
	 * @param  string|string[]|null  $roles
	 * @param  string|string[]|null  $resources
	 * @param  string|string[]|null  $privileges
	 * @return static
	 */
	public function allow(
		$roles = self::All,
		$resources = self::All,
		$privileges = self::All,
		?callable $assertion = null
	) {
		$this->setRule(true, self::Allow, $roles, $resources, $privileges, $assertion);
		return $this;
	}


	/**
	 * Denies one or more Roles access to [certain $privileges upon] the specified Resource(s).
	 * If $assertion is provided, then it must return true in order for rule to apply.
	 *
	 * @param  string|string[]|null  $roles
	 * @param  string|string[]|null  $resources
	 * @param  string|string[]|null  $privileges
	 * @return static
	 */
	public function deny(
		$roles = self::All,
		$resources = self::All,
		$privileges = self::All,
		?callable $assertion = null
	) {
		$this->setRule(true, self::Deny, $roles, $resources, $privileges, $assertion);
		return $this;
	}


	/**
	 * Removes "allow" permissions from the list in the context of the given Roles, Resources, and privileges.
	 *
	 * @param  string|string[]|null  $roles
	 * @param  string|string[]|null  $resources
	 * @param  string|string[]|null  $privileges
	 * @return static
	 */
	public function removeAllow($roles = self::All, $resources = self::All, $privileges = self::All)
	{
		$this->setRule(false, self::Allow, $roles, $resources, $privileges);
		return $this;
	}


	/**
	 * Removes "deny" restrictions from the list in the context of the given Roles, Resources, and privileges.
	 *
	 * @param  string|string[]|null  $roles
	 * @param  string|string[]|null  $resources
	 * @param  string|string[]|null  $privileges
	 * @return static
	 */
	public function removeDeny($roles = self::All, $resources = self::All, $privileges = self::All)
	{
		$this->setRule(false, self::Deny, $roles, $resources, $privileges);
		return $this;
	}


	/**
	 * Performs operations on Access Control List rules.
	 * @param  string|string[]|null  $roles
	 * @param  string|string[]|null  $resources
	 * @param  string|string[]|null  $privileges
	 * @throws Nette\InvalidStateException
	 * @return static
	 */
	protected function setRule(bool $toAdd, bool $type, $roles, $resources, $privileges, ?callable $assertion = null)
	{
		// ensure that all specified Roles exist; normalize input to array of Roles or null
		if ($roles === self::All) {
			$roles = [self::All];

		} else {
			if (!is_array($roles)) {
				$roles = [$roles];
			}

			foreach ($roles as $role) {
				$this->checkRole($role);
			}
		}

		// ensure that all specified Resources exist; normalize input to array of Resources or null
		if ($resources === self::All) {
			$resources = [self::All];

		} else {
			if (!is_array($resources)) {
				$resources = [$resources];
			}

			foreach ($resources as $resource) {
				$this->checkResource($resource);
			}
		}

		// normalize privileges to array
		if ($privileges === self::All) {
			$privileges = [];

		} elseif (!is_array($privileges)) {
			$privileges = [$privileges];
		}

		if ($toAdd) { // add to the rules
			foreach ($resources as $resource) {
				foreach ($roles as $role) {
					$rules = &$this->getRules($resource, $role, true);
					if (count($privileges) === 0) {
						$rules['allPrivileges']['type'] = $type;
						$rules['allPrivileges']['assert'] = $assertion;
						if (!isset($rules['byPrivilege'])) {
							$rules['byPrivilege'] = [];
						}
					} else {
						foreach ($privileges as $privilege) {
							$rules['byPrivilege'][$privilege]['type'] = $type;
							$rules['byPrivilege'][$privilege]['assert'] = $assertion;
						}
					}
				}
			}
		} else { // remove from the rules
			foreach ($resources as $resource) {
				foreach ($roles as $role) {
					$rules = &$this->getRules($resource, $role);
					if ($rules === null) {
						continue;
					}

					if (count($privileges) === 0) {
						if ($resource === self::All && $role === self::All) {
							if ($type === $rules['allPrivileges']['type']) {
								$rules = [
									'allPrivileges' => [
										'type' => self::Deny,
										'assert' => null,
									],
									'byPrivilege' => [],
								];
							}

							continue;
						}

						if ($type === $rules['allPrivileges']['type']) {
							unset($rules['allPrivileges']);
						}
					} else {
						foreach ($privileges as $privilege) {
							if (isset($rules['byPrivilege'][$privilege]) &&
								$type === $rules['byPrivilege'][$privilege]['type']
							) {
								unset($rules['byPrivilege'][$privilege]);
							}
						}
					}
				}
			}
		}

		return $this;
	}


	/********************* querying the ACL ****************d*g**/


	/**
	 * Returns true if and only if the Role has access to [certain $privileges upon] the Resource.
	 *
	 * This method checks Role inheritance using a depth-first traversal of the Role list.
	 * The highest priority parent (i.e., the parent most recently added) is checked first,
	 * and its respective parents are checked similarly before the lower-priority parents of
	 * the Role are checked.
	 *
	 * @param  string|Role|null  $role
	 * @param  string|Nette\Security\Resource|null  $resource
	 * @param  string|null  $privilege
	 * @throws Nette\InvalidStateException
	 */
	public function isAllowed($role = self::All, $resource = self::All, $privilege = self::All): bool
	{
		$this->queriedRole = $role;
		if ($role !== self::All) {
			if ($role instanceof Role) {
				$role = $role->getRoleId();
			}

			$this->checkRole($role);
		}

		$this->queriedResource = $resource;
		if ($resource !== self::All) {
			if ($resource instanceof Resource) {
				$resource = $resource->getResourceId();
			}

			$this->checkResource($resource);
		}

		do {
			// depth-first search on $role if it is not 'allRoles' pseudo-parent
			if (
				$role !== null
				&& ($result = $this->searchRolePrivileges($privilege === self::All, $role, $resource, $privilege)) !== null
			) {
				break;
			}

			if ($privilege === self::All) {
				if ($rules = $this->getRules($resource, self::All)) { // look for rule on 'allRoles' psuedo-parent
					foreach ($rules['byPrivilege'] as $privilege => $rule) {
						if (($result = $this->getRuleType($resource, null, $privilege)) === self::Deny) {
							break 2;
						}
					}

					if (($result = $this->getRuleType($resource, null, null)) !== null) {
						break;
					}
				}
			} elseif (($result = $this->getRuleType($resource, null, $privilege)) !== null) { // look for rule on 'allRoles' pseudo-parent
				break;
			} elseif (($result = $this->getRuleType($resource, null, null)) !== null) {
				break;
			}

			$resource = $this->resources[$resource]['parent']; // try next Resource
		} while (true);

		$this->queriedRole = $this->queriedResource = null;
		return $result ?? false;
	}


	/**
	 * Returns real currently queried Role. Use by assertion.
	 * @return mixed
	 */
	public function getQueriedRole()
	{
		return $this->queriedRole;
	}


	/**
	 * Returns real currently queried Resource. Use by assertion.
	 * @return mixed
	 */
	public function getQueriedResource()
	{
		return $this->queriedResource;
	}


	/********************* internals ****************d*g**/


	/**
	 * Performs a depth-first search of the Role DAG, starting at $role, in order to find a rule
	 * allowing/denying $role access to a/all $privilege upon $resource.
	 * @param  bool  $all (true) or one?
	 * @return mixed  null if no applicable rule is found, otherwise returns ALLOW or DENY
	 */
	private function searchRolePrivileges(bool $all, $role, $resource, $privilege)
	{
		$dfs = [
			'visited' => [],
			'stack' => [$role],
		];

		while (($role = array_pop($dfs['stack'])) !== null) {
			if (isset($dfs['visited'][$role])) {
				continue;
			}

			if ($all) {
				if ($rules = $this->getRules($resource, $role)) {
					foreach ($rules['byPrivilege'] as $privilege2 => $rule) {
						if ($this->getRuleType($resource, $role, $privilege2) === self::Deny) {
							return self::Deny;
						}
					}

					if (($type = $this->getRuleType($resource, $role, null)) !== null) {
						return $type;
					}
				}
			} else {
				if (($type = $this->getRuleType($resource, $role, $privilege)) !== null) {
					return $type;

				} elseif (($type = $this->getRuleType($resource, $role, null)) !== null) {
					return $type;
				}
			}

			$dfs['visited'][$role] = true;
			foreach ($this->roles[$role]['parents'] as $roleParent => $foo) {
				$dfs['stack'][] = $roleParent;
			}
		}

		return null;
	}


	/**
	 * Returns the rule type associated with the specified Resource, Role, and privilege.
	 * @param  string|null  $resource
	 * @param  string|null  $role
	 * @param  string|null  $privilege
	 * @return bool|null  null if a rule does not exist or assertion fails, otherwise returns ALLOW or DENY
	 */
	private function getRuleType($resource, $role, $privilege): ?bool
	{
		if (!$rules = $this->getRules($resource, $role)) {
			return null;
		}

		if ($privilege === self::All) {
			if (isset($rules['allPrivileges'])) {
				$rule = $rules['allPrivileges'];
			} else {
				return null;
			}
		} elseif (!isset($rules['byPrivilege'][$privilege])) {
			return null;

		} else {
			$rule = $rules['byPrivilege'][$privilege];
		}

		if ($rule['assert'] === null || $rule['assert']($this, $role, $resource, $privilege)) {
			return $rule['type'];

		} elseif ($resource !== self::All || $role !== self::All || $privilege !== self::All) {
			return null;

		} elseif ($rule['type'] === self::Allow) {
			return self::Deny;

		} else {
			return self::Allow;
		}
	}


	/**
	 * Returns the rules associated with a Resource and a Role, or null if no such rules exist.
	 * If the $create parameter is true, then a rule set is first created and then returned to the caller.
	 * @param  string|null  $resource
	 * @param  string|null  $role
	 */
	private function &getRules($resource, $role, bool $create = false): ?array
	{
		$null = null;
		if ($resource === self::All) {
			$visitor = &$this->rules['allResources'];
		} else {
			if (!isset($this->rules['byResource'][$resource])) {
				if (!$create) {
					return $null;
				}

				$this->rules['byResource'][$resource] = [];
			}

			$visitor = &$this->rules['byResource'][$resource];
		}

		if ($role === self::All) {
			if (!isset($visitor['allRoles'])) {
				if (!$create) {
					return $null;
				}

				$visitor['allRoles']['byPrivilege'] = [];
			}

			return $visitor['allRoles'];
		}

		if (!isset($visitor['byRole'][$role])) {
			if (!$create) {
				return $null;
			}

			$visitor['byRole'][$role]['byPrivilege'] = [];
		}

		return $visitor['byRole'][$role];
	}
}
