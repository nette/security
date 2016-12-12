<?php

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Security;

use Nette;


/**
 * Default implementation of IIdentity.
 *
 * @property   mixed $id
 * @property   array $roles
 * @property   array $data
 */
class Identity implements IIdentity
{
	use Nette\SmartObject {
		__get as private parentGet;
		__set as private parentSet;
		__isset as private parentIsSet;
	}

	/** @var mixed */
	private $id;

	/** @var array */
	private $roles;

	/** @var array */
	private $data;


	/**
	 * @param  mixed   identity ID
	 * @param  mixed   roles
	 * @param  array   user data
	 */
	public function __construct($id, $roles = NULL, $data = NULL)
	{
		$this->setId($id);
		$this->setRoles((array) $roles);
		$this->data = $data instanceof \Traversable ? iterator_to_array($data) : (array) $data;
	}


	/**
	 * Sets the ID of user.
	 * @param  mixed
	 * @return static
	 */
	public function setId($id)
	{
		$this->id = is_numeric($id) && !is_float($tmp = $id * 1) ? $tmp : $id;
		return $this;
	}


	/**
	 * Returns the ID of user.
	 * @return mixed
	 */
	public function getId()
	{
		return $this->id;
	}


	/**
	 * Sets a list of roles that the user is a member of.
	 * @param  array
	 * @return static
	 */
	public function setRoles(array $roles)
	{
		$this->roles = $roles;
		return $this;
	}


	/**
	 * Returns a list of roles that the user is a member of.
	 * @return array
	 */
	public function getRoles()
	{
		return $this->roles;
	}


	/**
	 * Returns a user data.
	 * @return array
	 */
	public function getData()
	{
		return $this->data;
	}


	/**
	 * Sets user data value.
	 * @param  string  property name
	 * @param  mixed   property value
	 * @return void
	 */
	public function __set($key, $value)
	{
		if ($this->parentIsSet($key)) {
			$this->parentSet($key, $value);

		} else {
			$this->data[$key] = $value;
		}
	}


	/**
	 * Returns user data value.
	 * @param  string  property name
	 * @return mixed
	 */
	public function &__get($key)
	{
		if ($this->parentIsSet($key)) {
			return $this->parentGet($key);

		} else {
			return $this->data[$key];
		}
	}


	/**
	 * Is property defined?
	 * @param  string  property name
	 * @return bool
	 */
	public function __isset($key)
	{
		return isset($this->data[$key]) || $this->parentIsSet($key);
	}

}
