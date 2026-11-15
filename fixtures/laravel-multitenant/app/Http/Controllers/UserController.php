<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class UserController extends Controller
{
    public function assignRole(Request $request, User $user)
    {
        $user->assignRole($request->role);

        return ['ok' => true];
    }

    public function avatar(Request $request)
    {
        $file = $request->file('avatar');
        $name = $file->getClientOriginalName();
        Storage::disk('public')->putFileAs('avatars', $file, $name);

        return ['path' => 'avatars/' . $name];
    }

    public function convert(Request $request)
    {
        $source = $request->input('source');
        $out = shell_exec('convert ' . $source . ' out.png');
        $prefs = unserialize($request->input('prefs'));

        return ['out' => $out, 'prefs' => $prefs];
    }
}
