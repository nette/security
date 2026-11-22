<?php declare(strict_types=1);

/**
 * This file is part of the Nette Framework (https://nette.org)
 * Copyright (c) 2004 David Grudl (https://davidgrudl.com)
 */

namespace Nette\Bridges\SecurityTracy;

use Nette;
use Nette\Security\{Principal, Vote, Voter};
use Tracy;
use function count, is_object;


/**
 * User panel for Debugger Bar.
 */
class UserPanel implements Tracy\IBarPanel
{
	/** @var array<string, array{principal: string, resource: string, privilege: string, votes: string, allowed: bool, undecided: bool, count: int}> */
	private array $decisions = [];


	public function __construct(
		private readonly Nette\Security\User $user,
	) {
		$user->onDecided[] = $this->recordDecision(...);
	}


	/**
	 * Renders tab.
	 */
	public function getTab(): ?string
	{
		if (!session_id() && !$this->decisions) {
			return null;
		}

		return Nette\Utils\Helpers::capture(function () {
			// a decision has already loaded the login state, so asking does not start the session
			$status = session_status() === PHP_SESSION_ACTIVE || $this->decisions
				? $this->user->isLoggedIn()
				: '?';
			require __DIR__ . '/dist/tab.phtml';
		});
	}


	/**
	 * Renders panel.
	 */
	public function getPanel(): ?string
	{
		if (session_status() !== PHP_SESSION_ACTIVE && !$this->decisions) {
			return null;
		}

		return Nette\Utils\Helpers::capture(function () {
			$user = $this->user;
			$decisions = $this->decisions;
			require __DIR__ . '/dist/panel.phtml';
		});
	}


	/** @param  list<array{Voter, Vote}>  $votes */
	private function recordDecision(
		Principal $principal,
		mixed $resource,
		string|\UnitEnum|null $privilege,
		array $votes,
		bool $allowed,
	): void
	{
		$described = [];
		$undecided = true;
		foreach ($votes as [$voter, $vote]) {
			$described[] = new \ReflectionClass($voter)->getShortName() . ': ' . $vote->name;
			$undecided = $undecided && $vote === Vote::Abstain;
		}

		$row = [
			'principal' => $principal->isLoggedIn() ? self::describe($principal->getIdentity()?->getId()) : 'guest',
			'resource' => self::describe($resource),
			'privilege' => self::describe($privilege),
			'votes' => implode(', ', $described),
			'allowed' => $allowed,
			'undecided' => $undecided,
		];
		$key = serialize($row);
		if (isset($this->decisions[$key])) {
			$this->decisions[$key]['count']++;
		} elseif (count($this->decisions) < 1000) {
			$this->decisions[$key] = $row + ['count' => 1];
		}
	}


	private static function describe(mixed $value): string
	{
		return match (true) {
			$value instanceof \UnitEnum => $value::class . '::' . $value->name,
			is_object($value) => $value::class,
			default => var_export($value, return: true),
		};
	}
}
