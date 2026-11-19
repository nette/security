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
- how to create custom authenticators and voters
- Access Control List

Documentation can be found on the [website](https://doc.nette.org/access-control).

It requires PHP version 8.4 and supports PHP up to 8.6.


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

The reason of the last logout can be obtained by method `$user->getLogoutReason()`, which returns either the constant `Nette\Security\User::LogoutInactivity` if the time expired or `User::LogoutManual` when the `logout()` method was called.

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

It is an object that verifies the login data, ie usually the name and password. The trivial implementation is the class `Nette\Security\SimpleAuthenticator`, which can be defined this way

```php
$authenticator = new Nette\Security\SimpleAuthenticator([
	# name => password
	'johndoe' => 'secret123',
	'kathy' => 'evenmoresecretpassword',
]);
```

This solution is more suitable for testing purposes. We will show you how to create an authenticator that will verify credentials against a database table.

An authenticator is an object that implements the `Nette\Security\Authenticator` interface with method `authenticate()`. Its task is either to return the so-called [identity](#Identity) or to throw an exception `Nette\Security\AuthenticationException`. It would also be possible to provide a fine-grained error code `Authenticator::IdentityNotFound` or `Authenticator::InvalidCredential`.

```php
use Nette;

class MyAuthenticator implements Nette\Security\Authenticator
{
	public function __construct(
		private Nette\Database\Explorer $database,
		private Nette\Security\Passwords $passwords,
	) {
	}

	public function authenticate(string $username, string $password): Nette\Security\IIdentity
	{
		$row = $this->database->table('users')
			->where('username', $username)
			->fetch();

		if (!$row) {
			throw new Nette\Security\AuthenticationException('User not found.', self::IdentityNotFound);
		}

		if (!$this->passwords->verify($password, $row->password)) {
			throw new Nette\Security\AuthenticationException('Invalid password.', self::InvalidCredential);
		}

		return new Nette\Security\SimpleIdentity(
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

Reading a key that was not passed throws `Nette\MemberAccessException`, so a typo does not go unnoticed.

Importantly, **when user logs out, identity is not deleted** and is still available. So, if identity exists, it by itself does not grant that the user is also logged in. The same holds for `$user->getId()`, which returns the ID of the retained identity even after logout, so never compare it to decide about ownership; that is what [voters](#voters) are for. If we want to explicitly delete the identity, we logout the user by `$user->logout(true)`.

Thanks to this, you can still assume which user is at the computer and, for example, display personalized offers in the e-shop, however, you can only display his personal data after logging in.

If you prefer the identity to be discarded on every logout and expiration, set `$user->persistIdentity = false`. Retaining the identity is best-effort and depends on the storage implementation.

Identity is an object that implements the `Nette\Security\IIdentity` interface, the default implementation is `Nette\Security\SimpleIdentity`. And as mentioned, identity is stored in the session, so if, for example, we change the role of some of the logged-in users, old data will be kept in the identity until he logs in again.


Guest Identity
--------------

You can provide an identity even for users who are not logged in. If the authenticator implements `IdentityHandler`, the identity returned by its method `getGuestIdentity()` is used as a fallback for `getIdentity()`, `getId()` and `getRoles()`. So anonymous visitors can carry their own roles and data instead of the plain `guest` role:

```php
public function getGuestIdentity(): ?Nette\Security\IIdentity
{
	return new Nette\Security\SimpleIdentity('guest', ['guest'], ['name' => 'Guest']);
}
```

An authenticator without a guest identity returns `null` from this method. The guest identity is resolved only when reading and is never stored.



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

The purpose of roles is to offer a more precise permission management and remain independent on the user name. As soon as user logs in, he is assigned one or more roles. Roles are simple names, for example, `admin`, `member`, `guest`, etc. They are specified in the second argument of `SimpleIdentity` constructor, either as a string or an array.

As an authorization criterion, we will now use the method `isInRole()`, which checks whether the user is in the given role:

```php
if ($user->isInRole('admin')) { // is the admin role assigned to the user?
	deleteItem(); // if so, he may delete an item
}
```

As you already know, logging the user out does not erase his identity. Thus, method `getIdentity()` still returns object `SimpleIdentity`, including all granted roles. The Nette Framework adheres to the principle of "less code, more security", so when you are checking roles, you do not have to check whether the user is logged in too. Method `isInRole()` works with **effective roles**, ie if the user is logged in, roles assigned to identity are used, if he is not logged in, an automatic special role `guest` (or the roles of the [guest identity](#guest-identity)) is used instead.


Voters
------

In addition to roles, we will introduce the terms resource and privilege:

- **role** is a user attribute - for example moderator, editor, visitor, registered user, administrator, ...
- **resource** is a logical unit of the application - article, page, user, menu item, poll, presenter, ...
- **privilege** is a specific activity, which user may or may not do with *resource* - view, edit, delete, vote, ...

Whether the user may perform a privilege with a resource is asked by the method `isAllowed()`:

```php
if ($user->isAllowed('file')) { // is user allowed to do everything with resource 'file'?
	useFile();
}

if ($user->isAllowed('file', 'delete')) { // is user allowed to delete a resource 'file'?
	deleteFile();
}

if ($user->isAllowed($article, 'edit')) { // is user allowed to edit this very article?
	editArticle($article);
}

if ($user->isAllowed(Article::class, 'create')) { // is user allowed to create articles?
	createArticle();
}
```

Both arguments are optional and their default value `null` means that no particular resource or privilege is asked about; what that means is up to the voters, for the ACL it is *everything*. The resource may be a name, an object or a class name.

The answer is decided by voters. A voter is an object implementing the `Nette\Security\Voter` interface with only one method `vote()`. It receives the user in the form of a [principal](#principal), the resource and the privilege, and returns one of the three cases of the enum `Nette\Security\Vote`: `Allow`, `Forbid`, or `Abstain` when it has nothing to allow. A voter usually takes care of one kind of resource and abstains on everything else. This one decides about articles, ie entities with properties `authorId` and `published`:

```php
use Nette\Security\{Principal, Vote, Voter};

class ArticleVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		if ($resource === Article::class) { // articles in general, such as whether one may create them
			return Vote::allowIf($privilege === 'create' && $principal->isInRole('registered'));

		} elseif (!$resource instanceof Article) { // not my business
			return Vote::Abstain;
		}

		return Vote::allowIf(match ($privilege) {
			'view' => $resource->published || $principal->hasId($resource->authorId),
			'edit', 'delete' => $principal->hasId($resource->authorId),
			default => false,
		});
	}
}
```

The guest may not edit the article, its author may:

```php
$article = new Article(authorId: 10);
$user->isAllowed($article, 'edit'); // false

$user->login($username, $password); // the author with ID 10
$user->isAllowed($article, 'edit'); // true
$user->isAllowed(new Article(authorId: 20), 'edit'); // false
```

`Vote::allowIf()` returns `Allow` if the condition holds and `Abstain` otherwise. That is the right answer of an ordinary voter, because "I do not allow it" is not "nobody may allow it". So an administrator may edit someone else's article thanks to another voter:

```php
class AdminVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($principal->isInRole('admin'));
	}
}
```

Keep in mind that a voter is asked about every resource and privilege, so an unconditional allow like this one really allows everything, including the resources of another kind of user and operations nobody should do. Narrow it to the resources it is meant for, or let the specific voters forbid what must not happen.

`Vote::Forbid` is written on purpose and rarely, for example for a banned user, who may do nothing whatever the other voters say:

```php
class BannedVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		return $principal->isInRole('banned') ? Vote::Forbid : Vote::Abstain;
	}
}
```

The votes are combined by one fixed rule: a single `Forbid` wins, otherwise a single `Allow` suffices, otherwise (also when all voters abstain) the access is not allowed. The order of voters therefore does not matter.

Voters are passed to the constructor of `User` or added by the method `addVoter()`. If there is no voter, `isAllowed()` throws `Nette\InvalidStateException` rather than silently denying everything.

```php
$user = new Nette\Security\User($storage, $authenticator, new ArticleVoter, new AdminVoter);
$user->addVoter(new BannedVoter);
```

In the DI container, every service implementing `Voter` is a voter automatically, even one with `autowired: false`, so it is enough to register it:

```neon
services:
	- ArticleVoter
	- AdminVoter
	- BannedVoter
```

The smallest site, with one administrator account defined in the `security: users:` section of the configuration and no roles, needs a single voter that allows everything to whoever is logged in:

```php
class LoggedInVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		return Vote::allowIf($principal->isLoggedIn());
	}
}
```

For such a site, plain `$user->isLoggedIn()` remains a legitimate authorization criterion too; the voter is needed only where something asks `isAllowed()`.

To avoid names written as string literals, the privilege may be a case of an enum, which the voters receive as it is. The enum need not be backed; give it string values only when the rules of the [ACL](#permission-acl), which are names, should apply to it. The voter checks the privilege together with the resource and decides in a `match` that static analysis checks for completeness:

```php
enum PostPrivilege
{
	case View;
	case Edit;
}

$user->isAllowed($post, PostPrivilege::Edit);

class PostVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		if (!$resource instanceof Post || !$privilege instanceof PostPrivilege) {
			return Vote::Abstain;
		}

		return Vote::allowIf(match ($privilege) {
			PostPrivilege::View => $resource->published || $principal->hasId($resource->authorId),
			PostPrivilege::Edit => $principal->hasId($resource->authorId),
		});
	}
}
```

A case of another enum, such as `ProfilePrivilege::Edit`, makes the voter abstain, so a mix-up cannot pass. For the same reason, the name `'edit'` and the case `PostPrivilege::Edit` are different things for a voter; use one or the other consistently.

A permission that has no object, such as an area of the site or a feature, can be asked about with a case of an enum as the resource, which the voter compares by identity. A concrete thing is asked about by the object and a kind of entity by its class name, like `Article::class` above, each with an enum privilege.

```php
enum Access
{
	case Admin;
	case Reports;
}

$user->isAllowed(Access::Admin);

// in the voter
return Vote::allowIf($resource === Access::Admin && $principal->isInRole('admin'));
```

A role-based authorizator implementing `Nette\Security\Authorizator`, which is asked about each role of the user, can still be set by the deprecated method `setAuthorizator()`, and an autowired service implementing it is used this way automatically. Write a voter instead.


Principal
---------

Voters do not receive the `User` object but `Nette\Security\Principal`, the user as authorization sees him:

- `getIdentity()` returns the identity only while the user is logged in, `null` for a guest, even when `User` retains the identity after logout or provides a guest identity
- `isLoggedIn()` checks whether the principal has an identity, ie the user is logged in or the principal was created for an identity by `createPrincipal()`
- `getGuestIdentity()` returns the [guest identity](#guest-identity) of a guest, `null` for a logged-in user, so a voter that needs the data of whoever it decides about reads `$principal->getIdentity() ?? $principal->getGuestIdentity()`
- `getRoles()` and `isInRole()` work with the effective roles
- `hasId($id)` checks whether this is the logged-in user with the given ID; it is always false for a guest, even for an article without an author (`null`), and it compares strictly, so `'10'` does not match `10`
- `isAllowed()` asks the voters, so a voter can delegate the decision:

```php
class CommentVoter implements Voter
{
	public function vote(Principal $principal, mixed $resource, string|\UnitEnum|null $privilege): Vote
	{
		// a comment may be viewed by whoever may view its article
		return Vote::allowIf(
			$resource instanceof Comment
			&& $privilege === 'view'
			&& $principal->isAllowed($resource->article, 'view'),
		);
	}
}
```

The principal of the current user is returned by `$user->getPrincipal()`. To decide about someone else, for example to whom to send a notification, or whether an anonymous visitor would see a page, create a principal of any identity by `createPrincipal()`, where `null` stands for a guest. It uses the same voters and roles, and the current user stays as he is:

```php
foreach ($subscribers as $identity) {
	if ($user->createPrincipal($identity)->isAllowed($article, 'view')) {
		sendNotification($identity, $article);
	}
}

$user->createPrincipal(null)->isAllowed($article, 'view'); // would a visitor see it?
```



Permission ACL
--------------

Nette comes with a built-in voter, the `Nette\Security\Permission` class, which offers a lightweight and flexible ACL (Access Control List) layer for permission and access control. When we work with this class, we define roles, resources, and individual permissions. And roles and resources may form hierarchies. To explain, we will show an example of a web application:

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

The ACL is a voter, so we pass it to the `User` like any other voter. In the DI container the sections `roles`, `resources` and `rules` of the `security` configuration create it and make it a voter by themselves. Then the ACL votes:

- `Allow` if any of the user's roles is allowed,
- `Forbid` if an explicit `deny()` rule stopped a role, so the rule `deny('administrator', 'poll', 'edit')` holds even when another voter allows it,
- `Abstain` if only the default deny-all applies, leaving the decision to the other voters,
- `Abstain` for a role or a resource it does not know, so it does not get in the way of the other voters, whereas calling `$acl->isAllowed()` directly with an unknown name throws an exception.

So the rules for the resource `article` do not apply to an `Article` object, unless the object implements `Nette\Security\Resource`, whose method `getResourceId()` returns the name of the resource:

```php
class Article implements Nette\Security\Resource
{
	public function getResourceId(): string
	{
		return 'article';
	}
}
```

Permissions can also be evaluated dynamically and we can leave the decision to our own callback. It receives the role and the resource of the rule that matched, which under inheritance may be ancestors of the queried ones; the queried names are returned by `$acl->getQueriedRole()` and `$acl->getQueriedResource()`:

```php
$assertion = function (Permission $acl, ?string $role, ?string $resource, ?string $privilege): bool {
	return ...;
};

$acl->allow('registered', 'comment', null, $assertion);
```

But the names of roles and resources are not enough when we would like to define that, for example, a user can edit an article only if he is its author. Such a decision depends on the data of the user and of the article, and it is the job of a voter like the `ArticleVoter` above, which works side by side with the ACL.

A role may inherit from one or more other roles. But what happens, if one ancestor has certain action allowed and the other one has it denied? Then the *role weight* comes into play - the last role in the array of roles to inherit has the greatest weight, first one the lowest:

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
$user->refreshStorage(); // if the user state was already read
```

[Continue...](https://doc.nette.org/en/security/authentication)
