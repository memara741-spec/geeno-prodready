<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $data = $request->validate(['email' => 'required|email', 'password' => 'required']);
        $user = User::where('email', $data['email'])->first();
        if (! $user || ! Hash::check($data['password'], $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 422);
        }

        return ['token' => $user->createToken('app', ['*'])->plainTextToken];
    }

    public function forgot(Request $request)
    {
        $request->validate(['email' => 'required|email']);

        return response()->json(['message' => 'If the address exists, a link was sent.']);
    }
}
