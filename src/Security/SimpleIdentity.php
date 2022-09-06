<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

declare(strict_types=1);

namespace Nette\Security;

use Nette;


/**
 * Default implementation of IIdentity.
 * @property   string|int $id
 * @property   array $roles
 * @property   array $data
 */
class SimpleIdentity implements IIdentity
{
	use Nette\SmartObject {
		__get as private parentGet;
		__set as private parentSet;
		__isset as private parentIsSet;
	}

	private string|int $id;
	private array $roles;
	private array $data;


	public function __construct($id, $roles = null, ?iterable $data = null)
	{
		$this->setId($id);
		$this->setRoles((array) $roles);
		$this->data = $data instanceof \Traversable
			? iterator_to_array($data)
			: (array) $data;
	}


	/**
	 * Sets the ID of user.
	 */
	public function setId(string|int $id): static
	{
		$this->id = is_numeric($id) && !is_float($tmp = $id * 1) ? $tmp : $id;
		return $this;
	}


	/**
	 * Returns the ID of user.
	 */
	public function getId(): string|int
	{
		return $this->id;
	}


	/**
	 * Sets a list of roles that the user is a member of.
	 */
	public function setRoles(array $roles): static
	{
		$this->roles = $roles;
		return $this;
	}


	/**
	 * Returns a list of roles that the user is a member of.
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}


	/**
	 * Returns a user data.
	 */
	public function getData(): array
	{
		return $this->data;
	}


	/**
	 * Sets user data value.
	 */
	public function __set(string $key, $value): void
	{
		if ($this->parentIsSet($key)) {
			$this->parentSet($key, $value);

		} else {
			$this->data[$key] = $value;
		}
	}


	/**
	 * Returns user data value.
	 */
	public function &__get(string $key): mixed
	{
		if ($this->parentIsSet($key)) {
			return $this->parentGet($key);

		} else {
			return $this->data[$key];
		}
	}


	public function __isset(string $key): bool
	{
		return isset($this->data[$key]) || $this->parentIsSet($key);
	}
}
