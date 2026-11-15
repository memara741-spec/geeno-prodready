<?php

namespace App\Http\Controllers;

use App\Models\Booking;
use Illuminate\Http\Request;

class BookingController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate(['room_id' => 'required|integer', 'date' => 'required|date']);

        if (Booking::where('room_id', $data['room_id'])->where('date', $data['date'])->exists()) {
            abort(409, 'Room already booked');
        }

        return Booking::create([
            'room_id' => $data['room_id'],
            'date' => $data['date'],
            'user_id' => $request->user()->id,
            'price' => $request->price,
            'status' => $request->status,
        ]);
    }
}
