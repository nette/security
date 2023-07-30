Nette Security: Access Control
==============================

[![Downloads this Month](https://img.shields.io/packagist/dm/nette/security.svg)](https://packagist.org/packages/nette/security)
[![Tests](https://github.com/nette/security/workflows/Tests/badge.svg?branch=master)](https://github.com/nette/security/actions)
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

It requires PHP version 7.2 and supports PHP up to 8.3.


[Support Me](https://github.com/sponsors/dg)
--------------------------------------------

Do you like Nette Security? Are you looking forward to the new features?

[![Buy me a coffee](https://files.nette.org/icons/donation-3.svg)](https://github.com/sponsors/dg)

Thank you!


Authentication
==============

Authentication means **user login**, ie. the process during which a user's identity is verified. The user usually identifies himself using username and password. Verification is performed by the so-called [authenticator](#Authenticator). If the login fails, it throws `Nette\Security\AuthenticationException`.

```php
try {
	$user->login($username, $password);
} catch (Nette\Security\AuthenticationException $e) {
	$this->flashMessage('The username or password you entered is incorrect.');
}
```

Logging him out:

```php
$user->logout();
```

And checking if user is logged in:

```php
echo $user->isLoggedIn() ? 'yes' : 'no';
```

Simple, right? And all security aspects are handled by Nette for you.

You can also set the time interval after which the user logs off (otherwise he logs off with session expiration). This is done by the method `setExpiration()`, which is called before `login()`. Specify a string with relative time as a parameter:

```php
// login expires after 30 minutes of inactivity
$user->setExpiration('30 minutes');

// cancel expiration
$user->setExpiration(null);
```

Expiration must be set to value equal or lower than the expiration of sessions.

The reason of the last logout can be obtained by method `$user->getLogoutReason()`, which returns either the constant `Nette\Security\IUserStorage::INACTIVITY` if the time expired or `IUserStorage::MANUAL` when the `logout()` method was called.

In presenters, you can verify login in the `startup()` method:

```php
protected function startup()
{
	parent::startup();
	if (!$this->getUser()->isLoggedIn()) {
		$this->redirect('Sign:in');
	}
}
```


Authenticator
-------------

It is an object that verifies the login data, ie usually the name and password. The trivial implementation is the class [Nette\Security\SimpleAuthenticator](https://api.nette.org/3.0/Nette/Security/SimpleAuthenticator.html), which can be defined this way

```php
$authenticator = new Nette\Security\SimpleAuthenticator([
	# name => password
	'johndoe' => 'secret123',
	'kathy' => 'evenmoresecretpassword',
]);
```

This solution is more suitable for testing purposes. We will show you how to create an authenticator that will verify credentials against a database table.

An authenticator is an object that implements the [Nette\Security\IAuthenticator](https://api.nette.org/3.0/Nette/Security/IAuthenticator.html) interface with method `authenticate()`. Its task is either to return the so-called [identity](#Identity) or to throw an exception `Nette\Security\AuthenticationException`. It would also be possible to provide an fine-grain error code `IAuthenticator::IDENTITY_NOT_FOUND` or `IAuthenticator::INVALID_CREDENTIAL`.

```php
use Nette;

class MyAuthenticator implements Nette\Security\IAuthenticator
{
	private $database;
	private $passwords;

	public function __construct(Nette\Database\Context $database, Nette\Security\Passwords $passwords)
	{
		$this->database = $database;
		$this->passwords = $passwords;
	}

	public function authenticate(array $credentials): Nette\Security\IIdentity
	{
		[$username, $password] = $credentials;

		$row = $this->database->table('users')
			->where('username', $username)
			->fetch();

		if (!$row) {
			throw new Nette\Security\AuthenticationException('User not found.');
		}

		if (!$this->passwords->verify($password, $row->password)) {
			throw new Nette\Security\AuthenticationException('Invalid password.');
		}

		return new Nette\Security\Identity(
			$row->id,
			$row->role, // or array of roles
			['name' => $row->username]
		);
	}
}
```

The MyAuthenticator class communicates with the database through [Nette Database Explorer](https://doc.nette.org/database) and works with table `users`, where column `username` contains the user's login name and column `password` contains [hash](https://doc.nette.org/passwords). After verifying the name and password, it returns the identity with user's ID, role (column `role` in the table), which we will mention [later ](#roles), and an array with additional data (in our case, the username).


$onLoggedIn, $onLoggedOut events
--------------------------------

Object `Nette\Security\User` has [events](https://doc.nette.org/smartobject#toc-events) `$onLoggedIn` and `$onLoggedOut`, so you can add callbacks that are triggered after a successful login or after the user logs out.


```php
$user->onLoggedIn[] = function () {
	// user has just logged in
};
```



Identity
========

An identity is a set of information about a user that is returned by the authenticator and which is then stored in a session and retrieved using `$user->getIdentity()`. So we can get the id, roles and other user data as we passed them in the authenticator:

```php
$user->getIdentity()->getId();
// also works shortcut $user->getId();

$user->getIdentity()->getRoles();

// user data can be access as properties
// the name we passed on in MyAuthenticator
$user->getIdentity()->name;
```

Importantly, **when user logs out, identity is not deleted** and is still available. So, if identity exists, it by itself does not grant that the user is also logged in. If we want to explicitly delete the identity, we logout the user by `$user->logout(true)`.

Thanks to this, you can still assume which user is at the computer and, for example, display personalized offers in the e-shop, however, you can only display his personal data after logging in.

Identity is an object that implements the [Nette\Security\IIdentity](https://api.nette.org/3.0/Nette/Security/IIdentity.html) interface, the default implementation is [Nette\Security\Identity](https://api.nette.org/3.0/Nette/Security/Identity.html). And as mentioned, identity is stored in the session, so if, for example, we change the role of some of the logged-in users, old data will be kept in the identity until he logs in again.



Authorization
=============

Authorization determines whether a user has sufficient privileges, for example, to access a specific resource or to perform an action. Authorization assumes previous successful authentication, ie that the user is logged in.

For very simple websites with administration, where user rights are not distinguished, it is possible to use the already known method as an authorization criterion `isLoggedIn()`. In other words: once a user is logged in, he has permissions to all actions and vice versa.

```php
if ($user->isLoggedIn()) { // is user logged in?
	deleteItem(); // if so, he may delete an item
}
```


Roles
-----

The purpose of roles is to offer a more precise permission management and remain independent on the user name. As soon as user logs in, he is assigned one or more roles. Roles themselves may be simple strings, for example, `admin`, `member`, `guest`, etc. They are specified in the second argument of `Identity` constructor, either as a string or an array.

As an authorization criterion, we will now use the method `isInRole()`, which checks whether the user is in the given role:

```php
if ($user->isInRole('admin')) { // is the admin role assigned to the user?
	deleteItem(); // if so, he may delete an item
}
```

As you already know, logging the user out does not erase his identity. Thus, method `getIdentity()` still returns object `Identity`, including all granted roles. The Nette Framework adheres to the principle of "less code, more security", so when you are checking roles, you do not have to check whether the user is logged in too. Method `isInRole()` works with **effective roles**, ie if the user is logged in, roles assigned to identity are used, if he is not logged in, an automatic special role `guest` is used instead.


Authorizator
------------

In addition to roles, we will introduce the terms resource and operation:

- **role** is a user attribute - for example moderator, editor, visitor, registered user, administrator, ...
- **resource** is a logical unit of the application - article, page, user, menu item, poll, presenter, ...
- **operation** is a specific activity, which user may or may not do with *resource* - view, edit, delete, vote, ...

An authorizer is an object that decides whether a given *role* has permission to perform a certain *operation* with specific *resource*. It is an object implementing the [Nette\Security\IAuthorizator](https://api.nette.org/3.0/Nette/Security/IAuthorizator.html) interface with only one method `isAllowed()`:

```php
class MyAuthorizator implements Nette\Security\IAuthorizator
{
	public function isAllowed($role, $resource, $operation): bool
	{
		if ($role === 'admin') {
			return true;
		}
		if ($role === 'user' && $resource === 'article') {
			return true;
		}

		...

		return false;
	}
}
```

And the following is an example of use. Note that this time we call the method `Nette\Security\User::isAllowed()`, not the authorizator's one, so there is not first parameter `$role`. This method calls `MyAuthorizator::isAllowed()` sequentially for all user roles and returns true if at least one of them has permission.

```php
if ($user->isAllowed('file')) { // is user allowed to do everything with resource 'file'?
	useFile();
}

if ($user->isAllowed('file', 'delete')) { // is user allowed to delete a resource 'file'?
	deleteFile();
}
```

Both arguments are optional and their default value means *everything*.



Permission ACL
--------------

Nette comes with a built-in implementation of the authorizer, the [Nette\Security\Permission](https://api.nette.org/3.0/Nette/Security/Permission.html) class, which offers a lightweight and flexible ACL (Access Control List) layer for permission and access control. When we work with this class, we define roles, resources, and individual permissions. And roles and resources may form hierarchies. To explain, we will show an example of a web application:

- `guest`: visitor that is not logged in, allowed to read and browse public part of the web, ie. read articles, comment and vote in polls
- `registered`: logged-in user, which may on top of that post comments
- `administrator`: can manage articles, comments and polls

So we have defined certain roles (`guest`, `registered` and `administrator`) and mentioned resources (`article`, `comments`, `poll`), which the users may access or take actions on (`view`, `vote`, `add`, `edit`).

We create an instance of the Permission class and define **roles**. It is possible to use the inheritance of roles, which ensures that, for example, a user with a role `administrator` can do what an ordinary website visitor can do (and of course more).

```php
$acl = new Nette\Security\Permission;

$acl->addRole('guest');
$acl->addRole('registered', 'guest'); // registered inherits from guest
$acl->addRole('administrator', 'registered'); // and administrator inherits from registered
```

We will now define a list of **resources** that users can access:

```php
$acl->addResource('article');
$acl->addResource('comment');
$acl->addResource('poll');
```

Resources can also use inheritance, for example, we can add `$acl->addResource('perex', 'article')`.

And now the most important thing. We will define between them **rules** determining who can do what:

```php
// everything is denied now

// let the guest view articles, comments and polls
$acl->allow('guest', ['article', 'comment', 'poll'], 'view');
// and also vote in polls
$acl->allow('guest', 'poll', 'vote');

// the registered inherits the permissions from guesta, we will also let him to comment
$acl->allow('registered', 'comment', 'add');

// the administrator can view and edit anything
$acl->allow('administrator', $acl::All, ['view', 'edit', 'add']);
```

What if we want to **prevent** someone from accessing a resource?

```php
// administrator cannot edit polls, that would be undemocractic.
$acl->deny('administrator', 'poll', 'edit');
```

Now when we have created the set of rules, we may simply ask the authorization queries:

```php
// can guest view articles?
$acl->isAllowed('guest', 'article', 'view'); // true

// can guest edit an article?
$acl->isAllowed('guest', 'article', 'edit'); // false

// can guest vote in polls?
$acl->isAllowed('guest', 'poll', 'vote'); // true

// may guest add comments?
$acl->isAllowed('guest', 'comment', 'add'); // false
```

The same applies to a registered user, but he can also comment:

```php
$acl->isAllowed('registered', 'article', 'view'); // true
$acl->isAllowed('registered', 'comment', 'add'); // true
$acl->isAllowed('registered', 'comment', 'edit'); // false
```

The administrator can edit everything except polls:

```php
$acl->isAllowed('administrator', 'poll', 'vote'); // true
$acl->isAllowed('administrator', 'poll', 'edit'); // false
$acl->isAllowed('administrator', 'comment', 'edit'); // true
```

Permissions can also be evaluated dynamically and we can leave the decision to our own callback, to which all parameters are passed:

```php
$assertion = function (Permission $acl, string $role, string $resource, string $privilege): bool {
	return ...;
};

$acl->allow('registered', 'comment', null, $assertion);
```

But how to solve a situation where the names of roles and resources are not enough, ie we would like to define that, for example, a role `registered` can edit a resource `article` only if it is its author? We will use objects instead of strings, the role will be the object [Nette\Security\IRole](https://api.nette.org/3.0/Nette/Security/IRole.html) and the source [Nette\Security\IResource](https://api.nette.org/3.0/Nette/Security/IResource.html). Their methods `getRoleId()` resp. `getResourceId()` will return the original strings:

```php
class Registered implements Nette\Security\IRole
{
	public $id;

	public function getRoleId(): string
	{
		return 'registered';
	}
}


class Article implements Nette\Security\IResource
{
	public $authorId;

	public function getResourceId(): string
	{
		return 'article';
	}
}
```

And now let's create a rule:

```php
$assertion = function (Permission $acl, string $role, string $resource, string $privilege): bool {
	$role = $acl->getQueriedRole(); // object Registered
	$resource = $acl->getQueriedResource(); // object Article
	return $role->id === $resource->authorId;
};

$acl->allow('registered', 'article', 'edit', $assertion);
```

The ACL is queried by passing objects:

```php
$user = new Registered(...);
$article = new Article(...);
$acl->isAllowed($user, $article, 'edit');
```

A role may inherit form one or more other roles. But what happens, if one ancestor has certain action allowed and the other one has it denied? Then the *role weight* comes into play - the last role in the array of roles to inherit has the greatest weight, first one the lowest:

```php
$acl = new Nette\Security\Permission;
$acl->addRole('admin');
$acl->addRole('guest');

$acl->addResource('backend');

$acl->allow('admin', 'backend');
$acl->deny('guest', 'backend');

// example A: role admin has lower weight than role guest
$acl->addRole('john', ['admin', 'guest']);
$acl->isAllowed('john', 'backend'); // false

// example B: role admin has greater weight than role guest
$acl->addRole('mary', ['guest', 'admin']);
$acl->isAllowed('mary', 'backend'); // true
```

Roles and resources can also be removed (`removeRole()`, `removeResource()`), rules can also be reverted (`removeAllow()`, `removeDeny()`). The array of all direct parent roles returns `getRoleParents()`. Whether two entities inherit from each other returns `roleInheritsFrom()` and `resourceInheritsFrom()`.


Multiple Independent Authentications
====================================

It is possible to have several independent logged users within one site and one session at a time. For example, if we want to have separate authentication for frontend and backend, we will just set a unique session namespace for each of them:

```php
$user->getStorage()->setNamespace('forum');
```
