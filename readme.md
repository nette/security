Nette Security: Access Control
==============================

[![Downloads this Month](https://img.shields.io/packagist/dm/nette/security.svg)](https://packagist.org/packages/nette/security)
[![Build Status](https://travis-ci.org/nette/security.svg?branch=master)](https://travis-ci.org/nette/security)
[![Coverage Status](https://coveralls.io/repos/github/nette/security/badge.svg?branch=master)](https://coveralls.io/github/nette/security?branch=master)
[![Latest Stable Version](https://poser.pugx.org/nette/security/v/stable)](https://github.com/nette/security/releases)
[![License](https://img.shields.io/badge/license-New%20BSD-blue.svg)](https://github.com/nette/security/blob/master/license.md)


Introduction
============

Authentication & Authorization library for Nette.

- user login and logout
- verifying user privileges
- securing against vulnerabilities
- how to create custom authenticators and authorizators
- Access Control List

Documentation can be found on the [website](https://doc.nette.org/access-control).

If you like Nette, **[please make a donation now](https://nette.org/donate)**. Thank you!


Installation
============

The recommended way to install is via Composer:

```
composer require nette/security
```

It requires PHP version 7.1 and supports PHP up to 7.4.


Authentication
==============

Authentication means **user login**, ie. the process during which user's identity is verified. User usually identifies himself using username and password.

Logging user in with username and password:

```php
$user->login($username, $password);
```

Checking if user is logged in:

```php
echo $user->isLoggedIn() ? 'yes' : 'no';
```

And logging him out:

```php
$user->logout();
```

Simple, right?

Logging in requires users to have cookies enabled - other methods are not safe!

Besides logging the user out with the `logout()` method, it can be done automatically based on specified time interval or closing the browser window. For this configuration we have to call `setExpiration()` during the login process. As an argument, it takes a relative time in seconds, UNIX timestamp, or textual representation of time.

```php
// login expires after 30 minutes of inactivity
$user->setExpiration('30 minutes');

// login expires after two days of inactivity
$user->setExpiration('2 days');
```

Expiration must be set to value equal or lower than the expiration of sessions.

The reason of last logout can be obtained by method `$user->getLogoutReason()`, which returns one of these constants: `IUserStorage::INACTIVITY` if time expired or `IUserStorage::MANUAL` when the `logout()` method was called.

To make the example above work, we in fact have to create an object that verifies user's name and password. It's called **authenticator**. Its trivial implementation is the class Nette\Security\SimpleAuthenticator, which in its constructor accepts an associative array:

```php
$authenticator = new Nette\Security\SimpleAuthenticator(array(
	'john' => 'IJ^%4dfh54*',
	'kathy' => '12345', // Kathy, this is a very weak password!
));
$user->setAuthenticator($authenticator);
```

If the login credentials are not valid, authenticator throws an Nette\Security\AuthenticationException:

```php
try {
	// we try to log the user in
	$user->login($username, $password);
	// ... and redirect upon success
	$this->redirect(...);

} catch (Nette\Security\AuthenticationException $e) {
	echo 'Login error: ', $e->getMessage();
}
```

We usually configure authenticator inside a config file, which only creates the object if it's requested by the application. The example above would be set in `config.neon` as follows:

```
services:
	authenticator: Nette\Security\SimpleAuthenticator([
			john: IJ^%4dfh54*
			kathy: 12345
		])
```


Custom authenticator
--------------------

We will create a custom authenticator that will check validity of login credentials against a database table. Every authenticator must be an implementation of Nette\Security\IAuthenticator, with its only method `authenticate()`. Its only purpose is to return an identity or to throw an `Nette\Security\AuthenticationException`. Framework defines few error codes, that can be used to determine the reason login was not successful, such as self-explaining `IAuthenticator::IDENTITY_NOT_FOUND` or `IAuthenticator::INVALID_CREDENTIAL`.

```php
use Nette\Security as NS;

class MyAuthenticator implements NS\IAuthenticator
{
	public $database;
	public $passwords;

	function __construct(Nette\Database\Connection $database, NS\Passwords $passwords)
	{
		$this->database = $database;
		$this->passwords = $password;
	}

	function authenticate(array $credentials)
	{
		list($username, $password) = $credentials;
		$row = $this->database->table('users')
			->where('username', $username)->fetch();

		if (!$row) {
			throw new NS\AuthenticationException('User not found.');
		}

		if (!$passwords->verify($password, $row->password)) {
			throw new NS\AuthenticationException('Invalid password.');
		}

		return new NS\Identity($row->id, $row->role);
	}
}
```

Class `MyAuthenticator` communicates with the database using Nette\Database layer and works with table `users`,  where it grabs `username` and hash of `password` in the appropriate columns. If the password check is successful, it returns new identity with user ID and role, which we will mention later;

This authenticator would be configured in the `config.neon` file like this:

```
services:
	authenticator: MyAuthenticator
```


Identity
--------

Identity presents a set of user information, as returned by autheticator. It's an object implementing Nette\Security\IIdentity interface, with default implementation Nette\Security\Identity.
Class has methods `getId()`, that returns users ID (for example primary key for the respective database row), and `getRoles()`, which returns an array of all roles user is in. User data can be access as if they were identity properties.

Identity is not erased when the user is logged out. So, if identity exists, it by itself does not grant that the user is also logged in. If we would like to explicitly delete the identity for some reason, we logout the user by calling `$user->logout(true)`.

Service `user` of class Nette\Security\User keeps the identity in session and uses it to all authorizations.
Identity can be access with `getIdentity` upon `$user`:

```php
if ($user->isLoggedIn()) {
	echo 'User logged in: ', $user->getIdentity()->getId();
} else {
	echo 'User is not logged in';
}
```



Authorization
=============

Authorization detects whether the user has enough privilege to do some action, for example opening a file or deleting an article. Authorization assumes that the user has been successfully authenticated (logged in).

Nette Framework authorization may be based on what groups the user belongs to or on which roles were assigned to the user. We will start from the very beginning.

For simple web sites with administration, where all users share same privileges, it is sufficient to use already mentioned `isLoggedIn()` method. Simply put, if the user is logged in, he has permissions to all actions, and vice versa.

```php
if ($user->isLoggedIn()) { // is user logged in?
	deleteItem(); // if so, he may delete an item
}
```


Roles
-----

The purpose of roles is to offer a more precise privilege control while remaining independent on the user name. As soon as user logs in, he is assigned one or more roles. Roles themselves may be simple strings, such as `admin`, `member`, `guest`, etc. They are specified in the second argument of `Identity` constructor, either as a string or an array.

This time we will use the `isInRole()` method to check if the user is allowed to perform some action:

```php
if ($user->isInRole('admin')) { // is the admin role assigned to the user?
	deleteItem(); // if so, he may delete an item
}
```

As you already know, logging user out does not erase his identity. Therefore the `getIdentity()` method still returns an `Identity` object, with all the assigned roles regardless on logout. Nette Framework adheres to the "less code, more security" principle, which is why it doesn't want to force coders to write `if ($user->isLoggedIn() && $user->isInRole('admin'))` everywhere and therefore the `isInRole()` method works with **efective roles**. If the user is logged in, roles assigned to identity are used, if he is logged out, an automatic special role `guest` is used instead.

Authorizator
------------

Authorizator decides, whether the user has permission to take some action. It's an implementation of Nette\Security\IAuthorizator interface with only one method `isAllowed()`. Purpose of this method is to determine, whether given role has the permission to perform certain *operation* with specific *resource*.

- **role** is a user attribute - for example moderator, editor, visitor, registered user, administrator, ...
- **resource** is a logical unit of the application - article, page, user, menu item, poll, presenter, ...
- **privilege** is a specific activity, which user may or may not do with *resource* - view, edit, delete, vote, ...


An implementation skeleton looks like this:

```php
class MyAuthorizator implements Nette\Security\IAuthorizator
{

	function isAllowed($role, $resource, $privilege)
	{
		return ...; // returns either true or false
	}

}
```

And an example of use:

```php
// registers the authorizator
$user->setAuthorizator(new MyAuthorizator);

if ($user->isAllowed('file')) { // is user allowed to do everything with resource 'file'?
	useFile();
}

if ($user->isAllowed('file', 'delete')) { // is user allowed to delete a resource 'file'?
	deleteFile();
}
```

Do not confuse two different methods `isAllowed`: one belongs to the authorizator and the other one to the `User` class, where first argument is not `$role`.

Because user may have many roles, he is granted the permission only if at least one of roles has the permission. Both arguments are optional and their default value is *everything*.


Permission ACL
--------------
Nette Framework has a complete authorizator, class Nette\Security\Permission which offers a light weight and flexible ACL((Access Control List)) layer for permission and access control. When we work with this class, we define roles, resources and individual privileges. Roles and resources may form hierarchies, as shown in the following example:

- `guest`: visitor that is not logged in, allowed to read and browse public part of the web, ie. articles, comments, and to vote in a poll

- `registered`: logged in user, which may on top of that post comments

- `administrator`: may write and administer articles, comments and polls

So we have defined certain roles (`guest`, `registered` and `administrator`) and metioned resources (`article`, `comments`, `poll`), which the users may access or take actions on (`view`, `vote`, `add`, `edit`).

We create an instance of Presmission and define the user roles. As roles may inherit each other, we may for example specify that `administrator` may do the same as an ordinary visitor (and of course more).

```php
$acl = new Nette\Security\Permission;

// roles definition
$acl->addRole('guest');
$acl->addRole('registered', 'guest'); // registered inherits from guest
$acl->addRole('administrator', 'registered'); // and administrator inherits from registered
```

Trivial, isn't it? This ensures all the properties of the parents will be inheritted by their children.

Do note the method `getRoleParents()`, which returns an array of all direct parent roles, and the method `roleIntheritsFrom()`, which checks whether a role extends another. Their usage:

```php
$acl->roleInheritsFrom('administrator', 'guest'); // true
$acl->getRoleParents('administrator'); // array('registered') - only direct parents
```

Now is the right time to define the set of resources that the users may acccess:

```php
$acl->addResource('article');
$acl->addResource('comments');
$acl->addResource('poll');
```

Also resources may use inheritance. The API offers similar methods, only the names are slightly different: `resourceInheritsFrom()`, `removeResource()`.

And now the most important part. Roles and resources alone would do us no good, we have to create rules defining who can do what with whatever:

TODO: missing example for deny()

```php
// everything is denied now

// guest may view articles, comments and polls
$acl->allow('guest', array('article', 'comments', 'poll'), 'view');

// registered user has also right to add comments
$acl->allow('registered', 'comments', 'add');

// administrator may also edit and add everything
$acl->allow('administrator', Permission::ALL, array('view', 'edit', 'add'));
```

Now when we have created the set of rules, we may simply ask the authorization queries:

```php
// can guest view articles?
echo $acl->isAllowed('guest', 'article', 'view'); // true
// can guest edit an article?
echo $acl->isAllowed('guest', 'article', 'edit'); // false
// may guest add comments?
echo $acl->isAllowed('guest', 'comments', 'add'); // false
```

The same is true for the registered user, though he is allowed to add a comment:

```php
echo $acl->isAllowed('registered', 'article', 'view'); // true
echo $acl->isAllowed('registered', 'comments', 'add'); // true
echo $acl->isAllowed('registered', 'backend', 'view'); // false
```

Administrator is allowed to do everything:

```php
echo $acl->isAllowed('administrator', 'article', 'view'); // true
echo $acl->isAllowed('administrator', 'commend', 'add'); // true
echo $acl->isAllowed('administrator', 'poll', 'edit'); // true
```

Admin rules may possibly be defined without any restrictions (without inheriting from any other roles):

```php
$acl->addRole('supervisor');
$acl->allow('supervisor');  // all privileges for all resources for supervisor
```

Whenever during the application runtime we may remove roles with `removeRolle()`, resources with `removeResource()` or rules with `removeAllow()` or `removeDeny()`.

Roles may inherit form one or more other roles. But what happens, if one ancestor has certain action allowed and the other one has it denied? Then the *role weight* comes into play - the last role in the array of roles to inherit has the greatest weight, first one the lowest:

```php
$acl = new Permission();
$acl->addRole('admin');
$acl->addRole('guest');

$acl->addResource('backend');

$acl->allow('admin', 'backend');
$acl->deny('guest', 'backend');

// example A: role admin has lower weight than role guest
$acl->addRole('john', array('admin', 'guest'));
$acl->isAllowed('john', 'backend'); // false

// example B: role admin has greater weight than role guest
$acl->addRole('mary', array('guest', 'admin'));
$acl->isAllowed('mary', 'backend'); // true
```


Multiple applications in one scope
==================================

Multiple applications may work on the same server, session, etc., each with separated authentication logic. We just have to set a unique namespace for each:

```php
$user->setNamespace('forum');
```
