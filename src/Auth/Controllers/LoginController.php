<?php

namespace Compredict\User\Auth\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{
	/*
	|--------------------------------------------------------------------------
	| Login Controller
	|--------------------------------------------------------------------------
	|
	| This controller handles authenticating users for the application and
	| redirecting them to your home screen. The controller uses a trait
	| to conveniently provide its functionality to your applications.
	|
	 */

	use AuthenticatesUsers;

	/**
	 * Where to redirect users after login.
	 *
	 * @var string
	 */
	protected $redirectTo = '/';

	/**
	 * Create a new controller instance.
	 *
	 * @return void
	 */
	public function __construct()
	{
		$this->middleware('guest')->except('logout');
	}

	/**
	 * Get the login username to be used by the controller.
	 *
	 * @return string
	 */
	public function username()
	{
		return 'username';
	}

	public function login(Request $request)
	{

		$this->validateLogin($request);

		if (!$request->filled('tac')) {
			return $this->sendFailedLoginResponse($request, [
				"tac" => "Please agree on the terms and conditions first.",
			]);
		}

		// If the class is using the ThrottlesLogins trait, we can automatically throttle
		// the login attempts for this application. We'll key this by the username and
		// the IP address of the client making these requests into this application.
		if (method_exists($this, 'hasTooManyLoginAttempts') &&
			$this->hasTooManyLoginAttempts($request)) {
			$this->fireLockoutEvent($request);

			return $this->sendLockoutResponse($request);
		}

		//ai core is throwing Exception here when the creeadintad are worng
		try {
			if ($this->attemptLogin($request)) {
				return $this->sendLoginResponse($request);
			}
		} catch (\Throwable $e) {
			return $this->sendFailedLoginResponse($request, null, $e);

		} catch (\Exception $e) {
			return $this->sendFailedLoginResponse($request, null, $e);
		}

		// If the login attempt was unsuccessful we will increment the number of attempts
		// to login and redirect the user back to the login form. Of course, when this
		// user surpasses their maximum number of attempts they will get locked out.
		$this->incrementLoginAttempts($request);

		return $this->sendFailedLoginResponse($request);

	}

	protected function sendFailedLoginResponse(Request $request, $validationError = null, $exception = null)
	{

		if (!empty($validationError)) {
			throw ValidationException::withMessages($validationError);
		}

		if (!empty($exception)) {
			throw ValidationException::withMessages([
				$this->username() => $exception->getMessage(),
			]);
		}

		$response = \CP_User::getLastError();
		if (!empty($response)) {
			if (isset($response->errors)) {
				$message = explode(':', $response->errors[0]);
				$message = $message[sizeof($message) - 1];
			} elseif (isset($response->error)) {
				$message = $response->error;
			} elseif (is_string($response)) {
				$message = $response;
			}
			throw ValidationException::withMessages([
				$this->username() => [$message],
			]);
		}

		$message = 'Somthing went wrong please try again.';
		throw ValidationException::withMessages([
			$this->username() => [$message],
		]);
	}

}
