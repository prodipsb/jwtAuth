<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Http\Requests\AuthRequest;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{

    public function register(AuthRequest $request){

        $validatedData = $request->validated();

        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => bcrypt($validatedData['password']),
        ]);

        $token = auth()->login($user);

        return $this->respondWithToken($token);

    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        $customClaims = [
            'user_id' => 1,
            'user_role' => 12, // Example of adding a user role
            'custom_data' => 'my data' // Any other custom data
        ];

        if ($token = $this->guard()->claims($customClaims)->attempt($credentials)) {

        

            return $this->respondWithToken($token);
        }

        return response()->json(['error' => 'Unauthorized'], 401);
    }


    public function getAuthenticatedUser()
{
    try {
        if (! $user = JWTAuth::parseToken()->authenticate()) {
            return response()->json(['user_not_found'], 404);
        }

    } catch (TokenExpiredException $e) {
        return response()->json(['token_expired'], $e->getStatusCode());

    } catch (TokenInvalidException $e) {
        return response()->json(['token_invalid'], $e->getStatusCode());

    } catch (JWTException $e) {
        return response()->json(['token_absent'], $e->getStatusCode());
    }

    // Access custom claims
    $token = JWTAuth::getToken();
    $payload = JWTAuth::getPayload($token)->toArray();
    $customData = $payload['custom_data'];

    return response()->json(compact('user', 'customData'));
}


    public function me()
    {
        return response()->json($this->guard()->user());
    }


    public function logout()
    {
        $this->guard()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }


    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }


    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ]);
    }


    public function guard()
    {
        return Auth::guard();
    }
}