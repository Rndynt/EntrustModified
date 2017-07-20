<?php namespace Zizaco\Entrust\Middleware;

/**
 * This file is part of Entrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Zizaco\Entrust
 */

use Closure;
use Illuminate\Contracts\Auth\Guard;

class EntrustRole
{
    const DELIMITER = '|';
	protected $auth;

	/**
	 * Creates a new instance of the middleware.
	 *
	 * @param Guard $auth
	 */
	public function __construct(Guard $auth)
	{
		$this->auth = $auth;
	}

	/**
	 * Handle an incoming request.
	 *
	 * @param  \Illuminate\Http\Request $request
	 * @param  Closure $next
	 * @param  $roles
	 * @return mixed
	 */
	public function handle($request, Closure $next, $roles)
	{
        if (!is_array($roles)) {
            $roles = explode(self::DELIMITER, $roles);
        }

        if ($this->auth->guest() || !$request->user()->hasRole($roles)){

            if ($request->user()->hasRole(explode('admins','feature-managers'))){
                return $next($request);
            }

            if ($this->auth->guest()){
                abort(403);
            }

            if (!$request->user()->hasRole('admins') || $this->auth->guest() || $request->user()->hasRole('customers')){
                return response()->view('errors.404-user',[], 404);
            }

        }

		return $next($request);
	}
}
